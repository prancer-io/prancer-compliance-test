



# Title: Ensure MariaDB servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-057

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mariadb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-057|
|eval|data.rule.mairadb_public_access_disabled|
|message|data.rule.mairadb_public_access_disabled_err|
|remediationDescription|In 'azurerm_mariadb_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_057.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for MariaDB Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mariadb_firewall_rule', 'azurerm_mariadb_server']


[mariadb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
