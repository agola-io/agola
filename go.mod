module agola.io/agola

go 1.12

require (
	code.gitea.io/gitea v1.9.4
	code.gitea.io/sdk/gitea v0.0.0-20191013013401-e41e9ea72caa
	github.com/Masterminds/squirrel v1.1.0
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/bmatcuk/doublestar v1.1.5
	github.com/containerd/continuity v0.0.0-20190827140505-75bee3e2ccb6 // indirect
	github.com/creack/pty v1.1.9 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/elazarl/goproxy v0.0.0-20190421051319-9d40249d3c2f // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190421051319-9d40249d3c2f // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-bindata/go-bindata v1.0.0
	github.com/go-ini/ini v1.49.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/google/go-cmp v0.3.1
	github.com/google/go-containerregistry v0.0.0-20191023194145-7683b4ee5f61
	github.com/google/go-github/v28 v28.1.1
	github.com/google/go-jsonnet v0.14.0
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.11.3 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/mattn/go-sqlite3 v1.11.0
	github.com/minio/minio-go v6.0.14+incompatible
	github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/opencontainers/runc v1.0.0-rc8 // indirect
	github.com/prometheus/client_golang v1.2.1 // indirect
	github.com/sanity-io/litter v1.2.0
	github.com/satori/go.uuid v1.2.0
	github.com/sgotti/gexpect v0.0.0-20161123102107-0afc6c19f50a
	github.com/spf13/cobra v0.0.5
	github.com/xanzy/go-gitlab v0.21.0
	go.etcd.io/etcd v0.0.0-20191023171146-3cf2f69b5738
	go.uber.org/multierr v1.2.0 // indirect
	go.uber.org/zap v1.11.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20191024073052-e66fe6eb8e0c // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20191009194640-548a555dbc03 // indirect
	gopkg.in/ini.v1 v1.49.0 // indirect
	gopkg.in/src-d/go-billy.v4 v4.3.2
	gopkg.in/src-d/go-git.v4 v4.13.1
	gopkg.in/yaml.v2 v2.2.4
	k8s.io/api v0.0.0-20191016110408-35e52d86657a
	k8s.io/apimachinery v0.0.0-20191004115801-a2eda9f80ab8
	k8s.io/client-go v0.0.0-20191016111102-bec269661e48
	k8s.io/utils v0.0.0-20190801114015-581e00157fb1
)

replace github.com/docker/docker v1.13.1 => github.com/docker/engine v0.0.0-20181106193140-f5749085e9cb
