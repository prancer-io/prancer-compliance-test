



# Master Test ID: PR-AZR-TRF-SQL-060


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mysql_server.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-060|
|eval|data.rule.mysql_public_access_disabled|
|message|data.rule.mysql_public_access_disabled_err|
|remediationDescription|In 'azurerm_mysql_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_060.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure MySQL servers don't have public network access enabled

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure MySQL Database Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mysql_firewall_rule', 'azurerm_mysql_server']


[mysql_server.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mysql_server.rego
