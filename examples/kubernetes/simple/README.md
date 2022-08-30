### Agola simple k8s test deployment

This is the simplest (and not production ready deployment).

- uses a local sqlite db.
- creates a `PersistentVolumeClaim` that will be used as the object storage container for all the components
- created a deployment with a single replica

You MUST NOT increase the replicas or every pod will uses a different sqlite db causing many issues and errors (and also the pods will fail if scheduled on different k8s node since the PV for the object storage cannot be mounted on multiple nodes)
