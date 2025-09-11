ARG AGOLAWEB_IMAGE="agola-web"

FROM $AGOLAWEB_IMAGE AS agola-web

#######
####### Build the backend
#######

# base build image
FROM golang:1.25-bookworm AS build_base

WORKDIR /agola

# use go modules
ENV GO111MODULE=on

# only copy go.mod and go.sum
COPY go.mod .
COPY go.sum .

RUN go mod download

# builds the agola binaries
FROM build_base AS server_builder

# copy all the sources
COPY . .

# copy the agola-web dist
COPY --from=agola-web /agola-web/dist/ /agola-web/dist/

RUN make WEBBUNDLE=1 WEBDISTPATH=/agola-web/dist

#######
####### Build the final image
#######
FROM debian:bookworm AS agola

WORKDIR /

# Install git needed by gitserver
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git && rm -rf /var/lib/apt/lists/*

# copy to agola binaries
COPY --from=server_builder /agola/bin/agola /agola/bin/agola-toolbox-* /bin/

ENTRYPOINT ["/bin/agola"]

#######
####### Build the demo image
#######

FROM agola AS agolademo

WORKDIR /

SHELL ["/bin/bash", "-c"]

RUN mkdir -p /data/agola/{configstore,runservice,executor,notification,gitserver}

ENTRYPOINT ["/bin/agola"]
