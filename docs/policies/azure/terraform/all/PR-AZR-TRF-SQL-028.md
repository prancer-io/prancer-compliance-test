



# Master Test ID: PR-AZR-TRF-SQL-028


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-028|
|eval|data.rule.geoRedundantBackup|
|message|data.rule.geoRedundantBackup_err|
|remediationDescription|In 'azurerm_postgresql_server' resource, set 'geo_redundant_backup_enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#geo_redundant_backup_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_028.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Geo-redundant backup is enabled on PostgreSQL database server.

***<font color="white">Description:</font>*** Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_postgresql_configuration', 'azurerm_postgresql_server', 'azurerm_postgresql_firewall_rule']


[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
