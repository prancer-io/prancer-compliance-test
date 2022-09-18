



# Title: Ensure Geo-redundant backup is enabled on MariaDB server.


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-058

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mariadb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-058|
|eval|data.rule.mariadb_geo_redundant_backup_enabled|
|message|data.rule.mariadb_geo_redundant_backup_enabled_err|
|remediationDescription|In 'azurerm_mariadb_server' resource, set 'geo_redundant_backup_enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#geo_redundant_backup_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_058.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Database for MariaDB provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mariadb_firewall_rule', 'azurerm_mariadb_server']


[mariadb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
