### Local development

#### Start the web interface

- Clone the [agola-web repository](https://github.com/agola-io/agola-web)

Inside the `agola-web` repository run:

``` sh
pnpm install
pnpm run serve
```

### Build the agola binary

To build agola we usually test and support the latest two major versions of Go like in the [Go release policy](https://golang.org/doc/devel/release.html#policy).

``` sh
make
```

### Start the agola server

- Copy the `example/agolademo/config.yml` where you prefer

- Some directories made need to be manually created by you. Create the `notification` and `gitserver` directories where specified in your `config.yml`. The other `dataDir` directories at run time

``` sh
./bin/agola serve --config /path/to/your/config.yml --components all-base,executor
```

### Error handling

Use the `--detailed-errors` option to easily follow the errors chain.

When developing you should wrap every error using `errors.Wrap[f]` or `errors.WithStack`. The ci uses `golangci-lint` with the `wrapcheck` linter enabled to check if some errors aren't wrapped.
