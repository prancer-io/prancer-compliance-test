



# Master Test ID: PR-AZR-TRF-SQL-066


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-066|
|eval|data.rule.postgresql_public_access_disabled|
|message|data.rule.postgresql_public_access_disabled_err|
|remediationDescription|In 'azurerm_postgresql_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_066.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure PostgreSQL servers don't have public network access enabled

***<font color="white">Description:</font>*** Always use Private Endpoint for PostgreSQL Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_postgresql_configuration', 'azurerm_postgresql_server', 'azurerm_postgresql_firewall_rule']


[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
