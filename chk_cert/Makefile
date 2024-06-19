# Read VERSION from an environment variable, default to "0.0.2" if not set
VERSION ?= 0.0.1
BUILD=$(shell date +%FT%T%z)

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS_f1=-ldflags "-w -s -X main.version=${VERSION} -X main.build=${BUILD}"

PLATFORMS := linux/amd64 windows/amd64 darwin/amd64 linux/arm64 windows/arm64 darwin/arm64

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
BINARY = chk_cert-$(os)-$(arch)-${VERSION}
release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 go build ${LDFLAGS_f1} -o '${BINARY}' .

clean:
	find . -name 'chk_cert[-?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete

.PHONY: release $(PLATFORMS) clean
