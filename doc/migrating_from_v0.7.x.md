## Migrating from v0.7.x

Agola versions after v0.7.x moved their internal db based on etcd and objectstorage to a standard external sql database (PostgreSQL or sqlite for single node deployments).

If you are going to update from a version <= v0.7.x you should do some manual steps to migrate the runservice and configstore data.

We suggest to test this migration on a test environment before doing this on your primary environment and keep backups.

1. Ensure you're using or update to the latest v0.7.x
1. Place somewhere the new agola > v0.7.x binary. In the next steps it'll be places in `/tmp`
1. Keep only the runservice and configstore services active. Stop the agola gateway to avoid external activity that will be lost by the backups taken in the next steps.
1. Take runservice and configstore backups

   `curl -v http://$RUNSERVICEHOST:PORT/api/v1alpha/export > /tmp/runservice-export`

   `curl -v http://$CONFIGSTOREHOST:PORT/api/v1alpha/export > /tmp/configstore-export`

1. Generate the migrated data using the new agola binary migrate command:

   `cat /tmp/runservice-export | ./tmp/agola migrate --service runservice > /tmp/runservice-migrated`

   `cat /tmp/runservice-export | ./tmp/agola migrate --service configstore > /tmp/configstore-migrated`

1. Update the agola binaries on your environment or use a test enviroment and start only the runservice and configstore.
1. Update the agola config file and remove the runservice, configstore, notification service etcd entries and add the db entries. Every component should have its own dedicated database. DO NOT use the same database for all the services. For PostgresSQL it can be the same postgres instance but with different databases.
1. Put the runservice and configstore in maintenance mode

   `curl -v -XPUT http://$NEWRUNSERVICEHOST:PORT/api/v1alpha/maintenance`

   `curl -v -XPUT http://$NEWCONFIGSTOREHOST:PORT/api/v1alpha/maintenance`

1. Import the migrated data

   `cat /tmp/runservice-migrated | curl -v -d @- http://$NEWRUNSERVICEHOST:PORT/api/v1alpha/import`

   `cat /tmp/configstore-migrated | curl -v -d @- http://$NEWCONFIGSTOREHOST:PORT/api/v1alpha/import`

1. Put the runservice and configstore in maintenance mode

   `curl -v -XDELETE http://$NEWRUNSERVICEHOST:PORT/api/v1alpha/maintenance`

   `curl -v -XDELETE http://$NEWCONFIGSTOREHOST:PORT/api/v1alpha/maintenance`

1. Start the gateway and test if the migration was successfull
