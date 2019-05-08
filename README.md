## Agola

CI/CD redefined

### Try it

See [the agolademo example](examples/agolademo)


### Local development

#### Start the web interface

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

```
make
```

### Start the agola server

* Copy the `example/config.yml` where you prefer

```
./bin/agola serve --toolbox-path $PWD/bin/agola-toolbox --embedded-etcd --config /path/to/your/config.yml
```

or use an external etcd:

```
./bin/agola serve --toolbox-path $PWD/bin/agola-toolbox --config /path/to/your/config.yml
```
