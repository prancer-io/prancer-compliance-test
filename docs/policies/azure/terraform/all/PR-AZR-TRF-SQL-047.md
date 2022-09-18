



# Title: Ensure SQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-047

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-047|
|eval|data.rule.mssql_public_access_disabled|
|message|data.rule.mssql_public_access_disabled_err|
|remediationDescription|In 'azurerm_mssql_server' resource, set 'public_network_access_enabled = false' to fix the issue. If 'public_network_access_enabled' property does not exist please add it. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_047.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_server', 'azurerm_private_endpoint']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego
