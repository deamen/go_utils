package runner

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactor(t *testing.T) {
	rd := newRedactor([]string{"TOKEN=s3cr3t-value", "SHORT=abc", "OTHER=another-secret=with=equals"})
	if got := rd.text("a s3cr3t-value b abc c another-secret=with=equals d"); got != "a [redacted TOKEN] b abc c [redacted OTHER] d" {
		t.Errorf("text = %q", got)
	}
	// A secret that arrives in pieces, of every size.
	in := "start s3cr3t-value middle another-secret=with=equals s3cr3t-values3cr3t-value end s3cr3t-"
	want := "start [redacted TOKEN] middle [redacted OTHER] [redacted TOKEN][redacted TOKEN] end s3cr3t-"
	for size := 1; size <= len(in); size++ {
		var out bytes.Buffer
		w := rd.writer(&out)
		for i := 0; i < len(in); i += size {
			n, err := w.Write([]byte(in[i:min(i+size, len(in))]))
			if err != nil || n != min(size, len(in)-i) {
				t.Fatalf("Write = %d, %v", n, err)
			}
		}
		if strings.Contains(out.String(), "s3cr3t-value") {
			t.Fatalf("pieces of %d: the secret was written before Flush: %q", size, out.String())
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Fatalf("pieces of %d:\n got %q\nwant %q", size, out.String(), want)
		}
	}
	// Nothing to redact: the writer passes everything on at once.
	var out bytes.Buffer
	w := newRedactor(nil).writer(&out)
	w.Write([]byte("plain"))
	if out.String() != "plain" {
		t.Errorf("without secrets: %q", out.String())
	}
	var none *redactor
	if none.text("x") != "x" {
		t.Error("a nil redactor changed the text")
	}
}
