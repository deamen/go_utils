package linear

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAPIURL       = "https://api.linear.app/graphql"
	DefaultTokenURL     = "https://api.linear.app/oauth/token"
	DefaultAuthorizeURL = "https://linear.app/oauth/authorize"
	// Scopes for an agent installed with actor=app.
	AgentScopes = "read,write,app:assignable,app:mentionable"
)

// Token is the OAuth token persisted in the token file.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitzero"`
}

func (t *Token) expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && now.Add(time.Minute).After(t.ExpiresAt)
}

// Client calls the Linear GraphQL API as the agent app user.
type Client struct {
	HTTP         *http.Client
	APIURL       string
	TokenURL     string
	ClientID     string
	ClientSecret string
	TokenFile    string

	mu    sync.Mutex
	token *Token
}

func NewClient(clientID, clientSecret, tokenFile string) *Client {
	return &Client{
		HTTP:         &http.Client{Timeout: 15 * time.Second},
		APIURL:       DefaultAPIURL,
		TokenURL:     DefaultTokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenFile:    tokenFile,
	}
}

var ErrNoToken = errors.New("no Linear OAuth token; run the linear-install flow first")

func (c *Client) loadToken() (*Token, error) {
	if c.token != nil {
		return c.token, nil
	}
	raw, err := os.ReadFile(c.TokenFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoToken
	}
	if err != nil {
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("token file %s: %w", c.TokenFile, err)
	}
	if t.AccessToken == "" {
		return nil, ErrNoToken
	}
	c.token = &t
	return c.token, nil
}

// SaveToken writes the token file with owner-only permissions.
func (c *Client) SaveToken(t *Token) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked(t)
}

func (c *Client) saveLocked(t *Token) error {
	raw, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.TokenFile); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := c.TokenFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.TokenFile); err != nil {
		return err
	}
	c.token = t
	return nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*Token, error) {
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("token endpoint: HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint: HTTP %d: %s %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
	}
	t := &Token{AccessToken: tr.AccessToken, TokenType: tr.TokenType, Scope: tr.Scope, RefreshToken: tr.RefreshToken}
	if tr.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t, nil
}

// Exchange trades an authorization code for a token (not yet saved).
func (c *Client) Exchange(ctx context.Context, code, redirectURL string) (*Token, error) {
	return c.tokenRequest(ctx, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURL},
	})
}

// accessToken returns a valid access token, refreshing it when expired.
func (c *Client) accessToken(ctx context.Context, forceRefresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, err := c.loadToken()
	if err != nil {
		return "", err
	}
	if (forceRefresh || t.expired(time.Now())) && t.RefreshToken != "" {
		nt, err := c.tokenRequest(ctx, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {t.RefreshToken},
		})
		if err != nil {
			return "", fmt.Errorf("refresh Linear token: %w", err)
		}
		if nt.RefreshToken == "" {
			nt.RefreshToken = t.RefreshToken
		}
		if err := c.saveLocked(nt); err != nil {
			return "", fmt.Errorf("save refreshed token: %w", err)
		}
		t = nt
	}
	return t.AccessToken, nil
}

type gqlError struct {
	Message string `json:"message"`
}

// Do executes a GraphQL request and decodes "data" into out (may be nil).
func (c *Client) Do(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, false)
	if err != nil {
		return err
	}
	return c.doWithToken(ctx, tok, body, out, true)
}

// doWithToken sends one request; on 401 it refreshes the token and retries
// once when mayRetry is set.
func (c *Client) doWithToken(ctx context.Context, tok string, body []byte, out any, mayRetry bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized && mayRetry {
		tok, err := c.accessToken(ctx, true)
		if err != nil {
			return err
		}
		return c.doWithToken(ctx, tok, body, out, false)
	}
	var gr struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlError      `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&gr); err != nil {
		return fmt.Errorf("linear api: HTTP %d: %w", resp.StatusCode, err)
	}
	if len(gr.Errors) > 0 {
		msgs := make([]string, len(gr.Errors))
		for i, e := range gr.Errors {
			msgs[i] = e.Message
		}
		return fmt.Errorf("linear api: HTTP %d: %s", resp.StatusCode, strings.Join(msgs, "; "))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("linear api: HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(gr.Data, out)
	}
	return nil
}

// Activity types accepted by agentActivityCreate.
const (
	ActivityThought  = "thought"
	ActivityResponse = "response"
	ActivityError    = "error"
	// ActivityElicitation asks the user for something; the session then
	// waits for their reply.
	ActivityElicitation = "elicitation"
)

const activityMutation = `mutation AgentActivityCreate($input: AgentActivityCreateInput!) {
  agentActivityCreate(input: $input) { success }
}`

// CreateActivity posts a thought, response or error to an agent session.
func (c *Client) CreateActivity(ctx context.Context, sessionID, kind, body string) error {
	return c.Do(ctx, activityMutation, map[string]any{
		"input": map[string]any{
			"agentSessionId": sessionID,
			"content":        map[string]any{"type": kind, "body": body},
		},
	}, nil)
}

const sessionUpdateMutation = `mutation AgentSessionUpdate($id: String!, $input: AgentSessionUpdateInput!) {
  agentSessionUpdate(id: $id, input: $input) { success }
}`

// SetExternalURL links the agent session to an external page (e.g. a run log).
func (c *Client) SetExternalURL(ctx context.Context, sessionID, label, link string) error {
	return c.Do(ctx, sessionUpdateMutation, map[string]any{
		"id":    sessionID,
		"input": map[string]any{"externalUrls": []map[string]string{{"label": label, "url": link}}},
	}, nil)
}

// Viewer identifies the app user and workspace behind the token.
type Viewer struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Organization struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"organization"`
}

func (c *Client) Viewer(ctx context.Context, tok string) (*Viewer, error) {
	body, _ := json.Marshal(map[string]any{"query": `{ viewer { id name organization { id name } } }`})
	var out struct {
		Viewer Viewer `json:"viewer"`
	}
	if err := c.doWithToken(ctx, tok, body, &out, false); err != nil {
		return nil, err
	}
	return &out.Viewer, nil
}

// AuthorizeURL builds the install URL for the agent app (actor=app).
func AuthorizeURL(clientID, redirectURL, state string) string {
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {AgentScopes},
		"actor":         {"app"},
		"state":         {state},
	}
	return DefaultAuthorizeURL + "?" + q.Encode()
}

// NewState returns a self-verifying OAuth state: "<expiry>.<nonce>.<hmac>".
// Only holders of the client secret can mint one, so the public callback
// cannot be abused to install the app into a foreign workspace.
func NewState(secret string, ttl time.Duration) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	payload := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10) + "." + hex.EncodeToString(nonce)
	return payload + "." + stateMAC(secret, payload)
}

func stateMAC(secret, payload string) string {
	m := hmac.New(sha256.New, []byte("linear-oauth-state:"+secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func VerifyState(secret, state string, now time.Time) error {
	i := strings.LastIndexByte(state, '.')
	if i < 0 {
		return errors.New("malformed state")
	}
	payload, mac := state[:i], state[i+1:]
	if !hmac.Equal([]byte(mac), []byte(stateMAC(secret, payload))) {
		return errors.New("invalid state signature")
	}
	exp, _, _ := strings.Cut(payload, ".")
	sec, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || now.After(time.Unix(sec, 0)) {
		return errors.New("state expired")
	}
	return nil
}
