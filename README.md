# Agola

[![Build Status](https://run.agola.io/api/v1alpha/badges/org%2Fagola%2Fagola?branch=master&)](https://run.agola.io/org/agola/projects/agola.proj)
[![Discourse](https://img.shields.io/discourse/https/talk.agola.io/status.svg)](https://talk.agola.io)

CI/CD redefined

For an introduction to agola you can take a look at [this post](https://sorintoss.io/blog/agola-introduction/)

<p float="left" align="center">
  <img src="https://agola.io/screenshots/screenshot_run_tasksgraph_01.png" height="340" />
  <img src="https://agola.io/screenshots/screenshot_run_01.png" height="340" />
</p>


## Try it

See [the agolademo example](https://agola.io/tryit)

## Features

* Easy to install and manage.
* Scalable and High Available: go from a single instance (single process) deployment to a distributed deployment.
* Deploy anywhere: Kubernetes, IaaS, bare metal and execute the "tasks" anywhere (currently containers executors like docker or orchestrators and Kubernetes, but easily extensible to future technologies or VMs instead of containers).
* Support any language, deployment system etc... (just use the right image)
* Integrate with multiple git providers at the same time: you could add repos from github, gitlab, gitea (and more to come) inside the same agola installation.
* Use it to manage the full development lifecycle: from build to deploy.
* Tasks Workflows (that we called **Runs**) with ability to achieve fan-in, fan-out, matrixes etc..., everything containerized to achieve maximum reproducibility.
* Git based workflow: the run definition is committed inside the git repository (so everything is tracked and reproducible). A run execution is started by a git action (push, pull-request).
* Design it with the ability to achieve at most once runs: during a deployment to production we don't want multiple concurrent execution of the deploy...
* Restartable and reproducible Runs (restart a run from scratch or from failed tasks using the same source commit, variables etc...)
* [User Direct Runs](https://agola.io/doc/concepts/user_direct_runs.html): give every user the power to test their software using the same run definition used when pushing to git/opening a pull request inside the Agola installation with just one command like if they were running tests locally (without requiring a super powerful workstation).
* Testable "Runs" (what is a CI/CD environment if you cannot test your changes to the Runs definitions?): use the same run definition but use a powerful [secrets and variables system](https://agola.io/doc/concepts/secrets_variables.html) to access different resources (environments, docker registries etc...).
* Don't try to extend YAML to be a templating language but use a real templating language (as of now [jsonnet](https://jsonnet.org/)) to easily generate the run configuration without side effects.
* An advanced permissions system (work in progress).
* Dependency Caching to speed up tasks

## Documentation

https://agola.io/doc/

## Local development

See [how to develop agola](doc/devel.md)

## Contributing to Agola

Agola is an open source project under the Apache 2.0 license, and contributions are gladly welcomed!
To submit your changes please open a pull request.

## Contacts
* For bugs and feature requests file an [issue](https://github.com/agola-io/agola/issues/new/choose)
* For general discussion about using and developing Agola, join the [agola forum](https://talk.agola.io)
