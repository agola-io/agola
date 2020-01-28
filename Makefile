PROJDIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# change to project dir so we can express all as relative paths
$(shell cd $(PROJDIR))

REPO_PATH=agola.io/agola

VERSION ?= $(shell scripts/git-version.sh)

LD_FLAGS="-w -X $(REPO_PATH)/cmd.Version=$(VERSION)"

$(shell mkdir -p bin )
$(shell mkdir -p tools/bin )

AGOLA_TAGS = sqlite_unlock_notify

AGOLA_WEBBUNDLE_DEPS = webbundle/bindata.go
AGOLA_WEBBUNDLE_TAGS = webbundle

ifdef WEBBUNDLE

ifndef WEBDISTPATH
$(error WEBDISTPATH must be provided when building the webbundle)
endif

AGOLA_DEPS = $(AGOLA_WEBBUNDLE_DEPS)
AGOLA_TAGS += $(AGOLA_WEBBUNDLE_TAGS)
endif

TOOLBOX_OSES=linux
TOOLBOX_ARCHS=amd64 arm64

.PHONY: all
all: build

.PHONY: build
build: agola agola-toolbox

# don't use existing file names and track go sources, let's do this to the go tool
.PHONY: agola
agola: $(AGOLA_DEPS)
	GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola $(REPO_PATH)/cmd/agola

# toolbox MUST be statically compiled so it can be used in any image for that arch
.PHONY: agola-toolbox
agola-toolbox:
	$(foreach GOOS, $(TOOLBOX_OSES),\
	$(foreach GOARCH, $(TOOLBOX_ARCHS), $(shell GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola-toolbox-$(GOOS)-$(GOARCH) $(REPO_PATH)/cmd/toolbox)))

.PHONY: go-bindata
go-bindata:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/go-bindata/go-bindata/go-bindata

.PHONY: gocovmerge
gocovmerge:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/wadey/gocovmerge

webbundle/bindata.go: go-bindata $(WEBDISTPATH)
	./tools/bin/go-bindata -o webbundle/bindata.go -tags webbundle -pkg webbundle -prefix "$(WEBDISTPATH)" -nocompress=true "$(WEBDISTPATH)/..."

.PHONY: docker-agola
docker-agola:
	docker build --target agola . -t agola

.PHONY: docker-agolademo
docker-agolademo:
	docker build . -t agolademo
