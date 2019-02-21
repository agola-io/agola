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

.PHONY: all
all: build

.PHONY: build
build: bin/agola bin/agola-toolbox

.PHONY: test
test: tools/bin/gocovmerge
	@scripts/test.sh

# don't use existing file names and track go sources, let's do this to the go tool
.PHONY: bin/agola
bin/agola:
	GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola $(REPO_PATH)/cmd/agola

# toolbox MUST be statically compiled so it can be used in any image for that arch
# TODO(sgotti) cross compile to multiple archs
.PHONY: bin/agola-toolbox
bin/agola-toolbox: 
	CGO_ENABLED=0 GO111MODULE=on go build $(if $(AGOLA_TAGS),-tags "$(AGOLA_TAGS)") -ldflags $(LD_FLAGS) -o $(PROJDIR)/bin/agola-toolbox $(REPO_PATH)/cmd/toolbox

.PHONY: tools/bin/gocovmerge
tools/bin/gocovmerge:
	GOBIN=$(PROJDIR)/tools/bin go install github.com/wadey/gocovmerge
