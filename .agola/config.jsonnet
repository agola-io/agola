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
    { type: 'run', command: 'SKIP_DOCKER_TESTS=1 go test -v -count 1 ./...' },
    { type: 'save_cache', key: 'cache-sum-{{ md5sum "go.sum" }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
    { type: 'save_cache', key: 'cache-date-{{ year }}-{{ month }}-{{ day }}', contents: [{ source_dir: '/go/pkg/mod/cache' }] },
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
    { type: 'run', name: 'build docker tests binary', command: 'CGO_ENABLED=0 go test -c ./internal/services/runservice/executor/driver -o ./bin/docker-tests' },
    { type: 'save_to_workspace', contents: [{ source_dir: './bin', dest_dir: '/bin/', paths: ['*'] }] },
  ],
};

{
  runs: [
    {
      name: 'agola build/test',
      tasks: std.flattenArrays([
        [
          task_build_go(version, arch),
          task_build_docker_tests(version, arch),
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
            { type: 'run', command: './bin/docker-tests -test.parallel 1 -test.v' },
          ],
          depends: [
            'build docker tests go 1.12 amd64',
          ],
        },
      ],
    },
  ],
}
