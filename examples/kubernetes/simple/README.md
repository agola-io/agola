### Agola simple k8s test deployment

This is the simplest (and not production ready deployment).

* uses an embedded etcd
* creates a `PersistentVolumeClaim` that will be used as the object storage container for all the components
* created a deployment with a single replica

You must not increase the replicas or every pod will uses a different embedded etcd causing many issues and errors (and also the pods will fail if scheduled on different k8s node since the PV for the object storage cannot be mounted on multiple nodes)

