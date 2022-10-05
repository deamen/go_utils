# These are the values we want to pass for VERSION and BUILD
# git tag 1.0.1
# git commit -am "One more change after the tags"
#VERSION=`git describe --tags`
VERSION="0.0.1"
BUILD=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS_f1=-ldflags "-w -s -X main.version=${VERSION} -X main.build=${BUILD}"

PLATFORMS := linux/amd64 windows/amd64 darwin/amd64 linux/arm64 windows/arm64 darwin/arm64

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
BINARY = chk_cert-$(os)-$(arch)
release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build ${LDFLAGS_f1} -o '${BINARY}' .

clean:
	find ${ROOT_DIR} -name 'chk_cert[-?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete


.PHONY: release $(PLATFORMS) clean
