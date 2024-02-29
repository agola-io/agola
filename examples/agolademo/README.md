# Agola demo

This demo uses [docker compose](https://docs.docker.com/compose/) to create containers, volumes, networks etc...

The demo will use only IPs to avoid users modifying local hosts file to resolve containers IPs.

Specifically:

* It'll create a custom bridged network (`agolademo_net1`) with subnet 172.30.0.0/16.
* It'll create docker volumes for agola and gitea containers.
* Start agola and gitea with a configuration suitable for the setup.

## Start

Move to the agolademo directory:

``` sh
cd examples/agolademo
```

Start the demo infrastructure

``` sh
docker compose up
```

## Connect

Point your browser to <http://172.30.0.2:8000>

You'll see the main agola ui page with a `Sign up` and a `Login` button at the top right. But before being able to register and login we should first link agola with gitea.

## Setup gitea

* Access gitea on <http://172.30.0.3:3000>
* Register a new user.
* Under your user `user settings` -> `SSH / GPG Keys` -> `Manage SSH Keys` add your ssh public key (to be able to push to repositories).
* Now create an oauth2 app under your `user settings` -> `Applications` -> `Manage OAuth2 Applications`. As the application name you can use `Agola` and as redirect uri use `http://172.30.0.2:8000/oauth2/callback`. Keep note of the provided `Client ID` and `Client Secret` and then click `Save`.

## Add a gitea remote source

A remote source defines a remote git provider (like gitea, gitlab, github).

The create a remote source we'll use the agola command in cli mode:

``` sh
docker run --network agolademo_net1 --rm sorintlab/agolademo --token "admintoken" --gateway-url http://172.30.0.2:8000 remotesource create \
--name gitea \
--type gitea \
--api-url http://172.30.0.3:3000 \
--auth-type oauth2 \
--clientid $GITEA_APP_CLIENTID \
--secret $GITEA_APP_CLIENTSECRET \
--skip-ssh-host-key-check
```

"admintoken" is a token defined in the default agolademo configuration and will let you act with the API as an admin without the need of a user created inside agola.

* `--skip-ssh-host-key-check` is used to speed up things and tells agola to not check gitea host ssh host key when cloning repositories. The right thing to do will be to provide the ssh host key using the option `--ssh-host-key`. You can get the host key using `ssh-keyscan $giteahost` and choosing the ecdsa or rsa host key provided line (use the whole line)

### Register

Login to the agola web ui on <http://172.30.0.2:8000> and choose **Sign up**, then **Register with gitea**. If everything goes well gitea will ask you Authorize the applicaton and then you'll be redirected back to the user registration form. Once registered you can Login.

### Create a user API Token

Use the web interface or the cli:

``` sh
docker run --network agolademo_net1 --rm sorintlab/agolademo --token admintoken --gateway-url http://172.30.0.2:8000 user token create -n $YOUR_AGOLA_USERNAME -t default
```

Save the token since it won't be displayed again.

#### Testing with an example repository

We'll use the [agola-example-go](https://github.com/agola-io/agola-example-go) repository

* Clone to above repository locally
* Create a repository on gitea called `agola-example-go`
* Create a project in agola connected to the gitea repository using the web interface or the cli:

``` sh
docker run --network agolademo_net1 --rm sorintlab/agolademo --token $TOKEN --gateway-url http://172.30.0.2:8000 project create \
--parent "user/$AGOLAUSER" \
--name agola-example-go \
--remote-source gitea \
--repo-path $GITEAUSER/agola-example-go
```

where:

* `--token` is your agola user API token
* `--name` is the agola project associated to your gitea repository that you want to create
* `--remote-source` is the remote source providing the repository
* `--repo-path` is the remote source repository path

* Push the `agola-example-go` repository you've previousy cloned to the gitea repository:

``` sh
git remote add mygitea git@172.30.0.3:$GITEAUSER/agola-example-go.git
git push -u mygitea master
```

If everything is ok, you should see a **run** started in the agola web ui (<http://172.30.0.2:8000>). If something went wrong you should take a look at the agola container logs.
