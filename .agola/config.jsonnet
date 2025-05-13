local go_runtime(version, arch) = {
  type: 'pod',
  arch: arch,
  containers: [
    {
      image: 'golang:' + version + '-bookworm',
    },
    {
      image: 'postgres:15',
      environment: {
        POSTGRES_PASSWORD: 'password',
      },
      entrypoint: 'docker-entrypoint.sh -c max_connections=300'
    },
  ],
};

local dind_runtime(arch) = {
  type: 'pod',
  arch: arch,
  containers: [
    {
      image: 'docker:23.0.1-dind',
      privileged: true,
      entrypoint: 'dockerd --bip 172.18.0.1/16',
    },
  ],
};

local task_build_go(version, arch) = {
  name: 'build go ' + version + ' ' + arch,
  runtime: go_runtime(version, arch),
  environment: {
    GO111MODULE: 'on',
  },
  steps: [
    { type: 'clone' },
    { type: 'restore_cache', keys: ['cache-sum-{{ md5sum "go.sum" }}', 'cache-date-'], dest_dir: '/go/pkg/mod/cache' },
    { type: 'run', command: 'make' },
    { type: 'save_cache', key: 'cache-sum-{{ md5sum "go.sum" }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
    { type: 'save_cache', key: 'cache-date-{{ year }}-{{ month }}-{{ day }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
    { type: 'run', name: 'install golangci-lint', command: 'curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.1.6' },
    { type: 'run', command: 'golangci-lint run --timeout 10m' },
    { type: 'run', name: 'build docker/k8s drivers tests binary', command: 'CGO_ENABLED=0 go test -c ./internal/services/executor/driver -o ./bin/docker-tests' },
    { type: 'run', name: 'build integration tests binary', command: 'go test -tags "sqlite_unlock_notify" -c ./tests -o ./bin/integration-tests' },
    { type: 'run', name: 'run tests (sqlite3)',
      environment: {
        DB_TYPE: "sqlite3",
        SKIP_DOCKER_TESTS: "1",
        SKIP_K8S_TESTS: "1",
      },
      command: 'go test -tags "sqlite_unlock_notify" -v -count 1 -parallel 5 $(go list ./... | grep -v agola.io/agola/tests)' },
    { type: 'run', name: 'run tests (postgres)',
      environment: {
        DB_TYPE: "postgres",
        PG_CONNSTRING: "postgres://postgres:postgres@localhost/%s?sslmode=disable",
        SKIP_DOCKER_TESTS: "1",
        SKIP_K8S_TESTS: "1",
      },
      command: 'go test -tags "sqlite_unlock_notify" -v -count 1 -parallel 5 $(go list ./... | grep -v agola.io/agola/tests)' },
    { type: 'run', name: 'fetch gitea binary for integration tests', command: 'curl -L https://github.com/go-gitea/gitea/releases/download/v1.15.11/gitea-1.15.11-linux-amd64 -o ./bin/gitea && chmod +x ./bin/gitea' },
    { type: 'save_to_workspace', contents: [{ source_dir: './bin', dest_dir: '/bin/', paths: ['*'] }] },
  ],
};

local task_build_docker_tests(version, arch) = {
  name: 'build docker tests go ' + version + ' ' + arch,
  runtime: go_runtime(version, arch),
  environment: {
    GO111MODULE: 'on',
  },
  steps: [
    { type: 'clone' },
    { type: 'restore_cache', keys: ['cache-sum-{{ md5sum "go.sum" }}', 'cache-date-'], dest_dir: '/go/pkg/mod/cache' },
  ],
};

local task_build_push_images(name, target, push) =
  /*
   * Currently, kaniko, has some issues with multi stage builds where it removes
   * all the files in the container after every stage (excluding /kaniko) causing
   * file not found errors when doing COPY commands.
   * Workaround this buy putting all files inside /kaniko
   */
  local options = if !push then '--no-push' else '--destination sorintlab/%s:$AGOLA_GIT_TAG' % [target];
  {
    name: name,
    runtime: {
      arch: 'amd64',
      containers: [
        {
          image: 'gcr.io/kaniko-project/executor:v1.9.1-debug',
        },
      ],
    },
    environment: {
      DOCKERAUTH: { from_variable: 'dockerauth' },
    },
    shell: '/busybox/sh',
    working_dir: '/kaniko',
    steps: [
      { type: 'restore_workspace', dest_dir: '/kaniko/agola' },
    ] + std.prune([
      if push then {
        type: 'run',
        name: 'generate docker auth',
        command: |||
          cat << EOF > /kaniko/.docker/config.json
          {
            "auths": {
              "https://index.docker.io/v1/": { "auth" : "$DOCKERAUTH" }
            }
          }
          EOF
        |||,
      },
    ]) + [
      { type: 'run', command: '/kaniko/executor --context=dir:///kaniko/agola --build-arg AGOLAWEB_IMAGE=sorintlab/agola-web:v0.10.0 --target %s %s' % [target, options] },
    ],
    depends: ['checkout code and save to workspace', 'integration tests', 'test docker driver'],
  };

{
  runs: [
    {
      name: 'agola build/test',
      tasks: std.flattenArrays([
        [
          task_build_go(version, arch),
        ]
        for version in ['1.23', '1.24']
        for arch in ['amd64' /*, 'arm64' */]
      ]) + [
        {
          name: 'test docker driver',
          runtime: dind_runtime('amd64'),
          steps: [
            { type: 'restore_workspace', dest_dir: '.' },
            { type: 'run', command: 'SKIP_K8S_TESTS=1 AGOLA_TOOLBOX_PATH="./bin" ./bin/docker-tests -test.parallel 5 -test.v' },
          ],
          depends: [
            'build go 1.24 amd64',
          ],
        },
        {
          name: 'integration tests',
          runtime: dind_runtime('amd64'),
          steps: [
            { type: 'run', command: 'apk update && apk add bash git openssh-keygen' },
            {
              type: 'run',
              name: 'install alpine glibc package',
              command: |||
                apk --no-cache add ca-certificates wget
                wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
                wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.34-r0/glibc-2.34-r0.apk
                apk del libc6-compat
                apk add --force-overwrite glibc-2.34-r0.apk
              |||,
            },
            { type: 'restore_workspace', dest_dir: '.' },
            { type: 'run', name: 'integration tests', command: 'AGOLA_BIN_DIR="./bin" GITEA_PATH=${PWD}/bin/gitea DOCKER_BRIDGE_ADDRESS="172.18.0.1" ./bin/integration-tests -test.parallel 3 -test.v' },
          ],
          depends: [
            'build go 1.24 amd64',
          ],
        },
        {
          name: 'checkout code and save to workspace',
          runtime: {
            arch: 'amd64',
            containers: [
              {
                image: 'alpine/git',
              },
            ],
          },
          steps: [
            { type: 'clone' },
            { type: 'save_to_workspace', contents: [{ source_dir: '.', dest_dir: '.', paths: ['**'] }] },
          ],
          depends: [],
        },
        task_build_push_images('test build docker "agola" image', 'agola', false) + {
          when: {
            branch: '#.*#',
            ref: '#refs/pull/\\d+/head#',
          },
        },
        task_build_push_images('test build docker "agolademo" image', 'agolademo', false) + {
          when: {
            branch: '#.*#',
            ref: '#refs/pull/\\d+/head#',
          },
        },
        task_build_push_images('build and push docker "agola" image', 'agola', true) + {
          when: {
            tag: '#v.*#',
          },
        },
        task_build_push_images('build and push docker "agolademo" image', 'agolademo', true) + {
          when: {
            tag: '#v.*#',
          },
        },
      ],
    },
  ],
}
