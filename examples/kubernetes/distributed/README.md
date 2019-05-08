### Agola distributed k8s deployment

This is a distributed deployment where all the components are replicated to achieve scaling and high availability

Users should use it as an example base setup and change/improve it based on their needs (choosing which object storage to use).

* point to an external etcd cluster
* points to an external s3 object storage.
* create 4 deployments for the various components with multiple replicas:
  * runservice
  * executor
  * configstore
  * gateway / scheduler


