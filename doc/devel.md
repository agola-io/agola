### Local development

#### Start the web interface

- Clone the [agola-web repository](https://github.com/agola-io/agola-web)

For the first time you'll need the `vue cli` and its services installed as global modules:

```
npm install -g @vue/cli @vue/cli-service-global
```

Inside the `agola-web` repository run:

```
npm install
npm run serve
```

### Build the agola binary

To build agola we usually test and support the latest two major versions of Go like in the [Go release policy](https://golang.org/doc/devel/release.html#policy).

```
make
```

### Start the agola server

- Copy the `example/agolademo/config.yml` where you prefer

```
./bin/agola serve --config /path/to/your/config.yml --components all-base,executor
```

### Error handling

Use the `--detailed-errors` option to easily follow the errors chain.

When developing you should wrap every error using `errors.Wrap[f]` or `errors.WithStack`. The ci uses `golangci-lint` with the `wrapcheck` linter enabled to check if some errors aren't wrapped.
