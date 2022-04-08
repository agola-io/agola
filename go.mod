module agola.io/agola

go 1.12

require (
	code.gitea.io/sdk/gitea v0.12.0
	github.com/Masterminds/squirrel v1.2.0
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/bmatcuk/doublestar v1.2.2
	github.com/containerd/continuity v0.0.0-20200107194136-26c1120b8d41 // indirect
	github.com/docker/docker v1.13.1
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v1.0.0
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/golang-jwt/jwt/v4 v4.0.0
	github.com/google/go-cmp v0.4.0
	github.com/google/go-containerregistry v0.0.0-20200212224832-c629a66d7231
	github.com/google/go-github/v29 v29.0.3
	github.com/google/go-jsonnet v0.15.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/lib/pq v1.10.4
	github.com/mattn/go-sqlite3 v1.14.6
	github.com/minio/minio-go/v6 v6.0.48
	github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.3
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/rs/zerolog v1.26.1
	github.com/sanity-io/litter v1.2.0
	github.com/sgotti/gexpect v0.0.0-20210315095146-1ec64e69809b
	github.com/spf13/cobra v0.0.5
	github.com/swaggo/files v0.0.0-20210815190702-a29dd2bc99b2
	github.com/swaggo/http-swagger v1.2.5
	github.com/swaggo/swag v1.7.9
	github.com/xanzy/go-gitlab v0.26.0
	go.starlark.net v0.0.0-20200203144150-6677ee5c7211
	golang.org/x/crypto v0.0.0-20211215165025-cf75a172585e
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/src-d/go-billy.v4 v4.3.2
	gopkg.in/src-d/go-git.v4 v4.13.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/client-go v0.17.3
	k8s.io/utils v0.0.0-20200124190032-861946025e34
)

replace github.com/docker/docker v1.13.1 => github.com/docker/engine v0.0.0-20200204220554-5f6d6f3f2203
