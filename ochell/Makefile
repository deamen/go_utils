# Read VERSION from an environment variable, default to "0.0.1" if not set
VERSION ?= 0.0.1
BUILD=$(shell date +%FT%T%z)

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS_f1=-ldflags "-w -s -X main.version=${VERSION} -X main.build=${BUILD}"

PLATFORMS := linux/amd64 windows/amd64 darwin/amd64 linux/arm64 windows/arm64 darwin/arm64

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
BINARY = ochell-$(os)-$(arch)-${VERSION}
release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 go build ${LDFLAGS_f1} -o '${BINARY}' .

test:
	go vet ./...
	go test -race ./...

# Binaries for the VM-only tests, to copy to the VM (README, "Tests on the VM").
vmtest:
	mkdir -p vmtest
	GOOS=linux CGO_ENABLED=0 go build -o vmtest/ochell .
	GOOS=linux CGO_ENABLED=0 go build -o vmtest/fakeagent ./e2e/fakeagent
	GOOS=linux CGO_ENABLED=0 go test -c -o vmtest/e2e.test ./e2e

clean:
	find . -name 'ochell[-?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete
	rm -rf vmtest

.PHONY: release $(PLATFORMS) test vmtest clean
