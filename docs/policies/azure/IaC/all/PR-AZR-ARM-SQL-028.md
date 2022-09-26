



# Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-028

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-028|
|eval|data.rule.geoRedundantBackup|
|message|data.rule.geoRedundantBackup_err|
|remediationDescription|In Resource of type "Microsoft.dbforpostgresql/servers" make sure properties.storageProfile.geoRedundantBackup exists and value is set to "Enabled".<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_028.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbforpostgresql/servers']


[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego
