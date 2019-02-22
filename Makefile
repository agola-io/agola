PROJDIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# change to project dir so we can express all as relative paths
$(shell cd $(PROJDIR))

PROJ=agola
ORG_PATH=github.com/sorintlab
REPO_PATH=$(ORG_PATH)/$(PROJ)

VERSION ?= $(shell scripts/git-version.sh)

LD_FLAGS="-w -X $(REPO_PATH)/version.Version=$(VERSION)"

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

.PHONY: all
all: build

.PHONY: build
build: bin/agola bin/agola-toolbox bin/agola-git-hook

.PHONY: test
test: tools/bin/gocovmerge
	@scripts/test.sh

# don't use existing file names and track go sources, let's do this to the go tool
.PHONY: bin/agola
bin/agola: $(AGOLA_DEPS)
	GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola $(REPO_PATH)/cmd/agola

# toolbox MUST be statically compiled so it can be used in any image for that arch
# TODO(sgotti) cross compile to multiple archs
.PHONY: bin/agola-toolbox
bin/agola-toolbox: 
	CGO_ENABLED=0 GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola-toolbox $(REPO_PATH)/cmd/toolbox

.PHONY: tools/bin/go-bindata
tools/bin/go-bindata:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/go-bindata/go-bindata/go-bindata

.PHONY: bin/agola-git-hook
bin/agola-git-hook:
	CGO_ENABLED=0 GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola-git-hook $(REPO_PATH)/cmd/agola-git-hook

.PHONY: tools/bin/gocovmerge
tools/bin/gocovmerge:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/wadey/gocovmerge

webbundle/bindata.go: tools/bin/go-bindata $(WEBDISTPATH)
	./tools/bin/go-bindata -o webbundle/bindata.go -tags webbundle -pkg webbundle -prefix "$(WEBDISTPATH)" -nocompress=true "$(WEBDISTPATH)/..."