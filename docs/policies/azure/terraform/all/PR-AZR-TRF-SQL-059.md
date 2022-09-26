



# Title: MariaDB server should use private link


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-059

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mariadb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-059|
|eval|data.rule.mariadb_server_uses_privatelink|
|message|data.rule.mariadb_server_uses_privatelink_err|
|remediationDescription|'azurerm_mariadb_server' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_mariadb_server' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_059.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your MariaDB Server instances, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mariadb_server', 'azurerm_private_endpoint']


[mariadb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
