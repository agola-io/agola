#######
####### Build the backend
#######

# Base build image
FROM golang:1.11 AS build_base

WORKDIR /agola

# use go modules
ENV GO111MODULE=on

# Only copy go.mod and go.sum
COPY go.mod .
COPY go.sum .

RUN go mod download

# This image builds the weavaite server
FROM build_base AS server_builder

# Copy all the source
COPY . .

# Copy the agola-web dist
COPY --from=agola-web /agola-web/dist/ /agola-web/dist/

RUN make WEBBUNDLE=1 WEBDISTPATH=/agola-web/dist


#######
####### Build the final image
#######
FROM debian:stable AS agola

WORKDIR /

# Finally we copy the statically compiled Go binary.
COPY --from=server_builder /agola/bin/agola /agola/bin/agola-toolbox /bin/

ENTRYPOINT ["/bin/agola"]


#######
####### Build the demo image
#######

FROM agola as agolademo

WORKDIR /

# Install git needed by gitserver
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the example config
COPY examples/config.yml .

ENTRYPOINT ["/bin/agola"]
