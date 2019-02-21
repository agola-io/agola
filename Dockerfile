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
#RUN go build -tags "sqlite_unlock_notify webbundle" -o /go/bin/agola ./cmd/agola
#RUN CGO_ENABLED=0 go build -tags "sqlite_unlock_notify webbundle" -o /go/bin/agola-toolbox ./cmd/toolbox


#######
####### Build the final image
#######
FROM debian:stable

WORKDIR /go/src/github.com/sorintlab/agola

# Finally we copy the statically compiled Go binary.
COPY --from=server_builder /agola/bin/agola /agola/bin/agola-toolbox /bin/
ENTRYPOINT ["/bin/agola"]