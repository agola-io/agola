# Trying Agola Demo

### Building the agolademo image

The demo setup will make you test agola with a gitea server

#### Clone agola repository

```
git clone git@wecode.sorint.it:agola/agola.git
```

#### Clone agola-web repository

```
git clone git@wecode.sorint.it:agola/agola-web.git
```

#### Build agola web

The agolademo image will embedd the agola-web frontend. So at first lets build the agola web image that will be used by the next step

From the agola-web repository:

```
docker build . -t agola-web
```

#### Create agolademo docker image

From the agola repository:

```
docker build . -t agolademo
```

### Test environment with a local gitea instance using docker

First annotate your docker bridge local network address. Usually it's `172.17.0.1`. This is needed to correctly setup gitea and agola to communicate togheter without using docker links or a more complex network setup.

#### Start gitea local demo

NOTE: if you have an ssh server running locally you should stop it

```
docker run -d --name gitea -v /tmp/gitea-data:/data -p 3000:3000 -p 22:22 gitea/gitea:latest
```

This will save your gitea data inside your host `/tmp/gitea` directory

#### Setup gitea

* Access gitea on `http://localhost:3000`
* In the initial setup page you should change:
   * the *Gitea Base URL* to `http://$YOURDOCKERLOCALIP:3000` (i.e. `http://172.17.0.1:3000`)
   * the *SSH Server Domain* to `$YOURDOCKERLOCALIP` (i.e. `172.17.0.1`)
* Register a new user
* Under your user settings, add your ssh public key (to be able to push to repositories)

#### Start the agola docker demo

```
docker run \
-v=/var/run/docker.sock:/var/run/docker.sock \
-v=/tmp/agola-data:/tmp/agola \
-p 8000:8000 \
agolademo \
serve --embedded-etcd --components all
```


#### Adding a remote source

### Add a gitea remote source

A remote source defines a remote git provider (like gitea, gitlab)

Gitea only recently provided a oauth2 provider (https://github.com/go-gitea/gitea/pull/5378). For old version we can just use the old username/password flow to create an user api token 

```
docker run --rm agolademo --token "admintoken" --gateway-url http://172.17.0.1:8000 remotesource create \
--name gitea \
--type gitea \
--api-url http://172.17.0.1:3000 \
--auth-type password
--skip-ssh-host-key-check
```

"admintoken" is a token defined in the default agolademo configuration and will let you act with the api as an admin without the need of an user created inside agola.

* `--skip-ssh-host-key-check` is used to speed up things and tells agola to not check gitea host ssh host key when cloning repositories. The right thing to do will be to provide the ssh host key using the option `--ssh-host-key`. You can get the host key using `ssh-keyscan $giteahost` and choosing the ecdsa or rsa host key provided line (use the whole line)

### Register

Login to the agola web ui and choose register, then **register with gitea**

### Create a user api token

```
docker run --rm agolademo --token admintoken --gateway-url http://172.17.0.1:8000 user token create -n $USER -t default
```

or do the same using the ui (under **User Settings**)

#### Testing with an example repository

We'll use the [agola-example-go](https://wecode.sorint.it/agola/agola-example-go) repository
* Clone to above repository locally

* Create a repository on gitea called `agola-example-go`

* Setup the repository to work with agola:
```
docker run --rm agolademo --token $TOKEN --gateway-url http://172.17.0.1:8000 project create \
--parent "user/$AGOLAUSER" \
--name agola-example-go \
--remote-source gitea \
--repo-path $GITEAUSER/agola-example-go \
--skip-ssh-host-key-check
```


where:
* `--token` is your agola user api token
* `--name` is the agola project associated to your gitea repository that you want to create
* `--remote-source` is the remote source providing the repository
* `--repo-path` is the remote source repository path
* `--skip-ssh-host-key-check` is required since your gitea server doesn't have a known ssh public key


* Push the `agola-example-go` repository you've previousy cloned to the gitea repository, for example: (**But you should already know hot git works... right?**)

```
git remote add mygitea git@172.17.0.1:$GITEAUSER/agola-example-go.git
git push -u mygitea master
```

If everything is ok, you should see a **run** started in the agola web ui (http://localhost:8000). Or take a look at the agola container logs to see what has failed.


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