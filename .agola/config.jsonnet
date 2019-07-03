local go_runtime(version, arch) = {
  type: 'pod',
  arch: arch,
  containers: [
    {
      image: 'golang:' + version + '-stretch',
    },
  ],
};

local dind_runtime(arch) = {
  type: 'pod',
  arch: arch,
  containers: [
    {
      image: 'docker:stable-dind',
      privileged: true,
      entrypoint: 'dockerd',
    },
  ],
};

local task_build_go(version, arch) = {
  name: 'build go ' + version + ' ' + arch,
  runtime: go_runtime(version, arch),
  environment: {
    GO111MODULE: 'on',
    VAR01: {
      from_variable: 'var01',
    },
  },
  steps: [
    { type: 'run', command: 'env' },
    { type: 'clone' },
    { type: 'restore_cache', keys: ['cache-sum-{{ md5sum "go.sum" }}', 'cache-date-'], dest_dir: '/go/pkg/mod/cache' },
    { type: 'run', command: 'make' },
    { type: 'save_cache', key: 'cache-sum-{{ md5sum "go.sum" }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
    { type: 'save_cache', key: 'cache-date-{{ year }}-{{ month }}-{{ day }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
    { type: 'run', name: 'install golangci-lint', command: 'curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin v1.17.1' },
    { type: 'run', command: 'golangci-lint run --deadline 5m' },
    { type: 'run', name: 'build docker/k8s drivers tests binary', command: 'CGO_ENABLED=0 go test -c ./internal/services/executor/driver -o ./bin/docker-tests' },
    { type: 'run', name: 'run tests', command: 'SKIP_DOCKER_TESTS=1 SKIP_K8S_TESTS=1 go test -v -count 1 ./...' },
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
    { type: 'run', command: 'env' },
    { type: 'clone' },
    { type: 'restore_cache', keys: ['cache-sum-{{ md5sum "go.sum" }}', 'cache-date-'], dest_dir: '/go/pkg/mod/cache' },
  ],
};

{
  runs: [
    {
      name: 'agola build/test',
      tasks: std.flattenArrays([
        [
          task_build_go(version, arch),
        ]
        for version in ['1.11', '1.12']
        for arch in ['amd64' /*, 'arm64' */]
      ]) + [
        {
          name: 'test docker driver',
          runtime: dind_runtime('amd64'),
          steps: [
            { type: 'run', command: 'env' },
            { type: 'restore_workspace', dest_dir: '.' },
            { type: 'run', command: 'SKIP_K8S_TESTS=1 AGOLA_TOOLBOX_PATH="./bin" ./bin/docker-tests -test.parallel 1 -test.v' },
          ],
          depends: [
            'build go 1.12 amd64',
          ],
        },
      ],
    },
  ],
}
