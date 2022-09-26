



# Title: Ensure Security Alert is enabled on Azure SQL Server


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-030

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-030|
|eval|data.rule.sql_server_alert|
|message|data.rule.sql_server_alert_err|
|remediationDescription|Make sure resource 'azurerm_sql_server' and 'azurerm_mssql_server_security_alert_policy' both exist and in 'azurerm_mssql_server_security_alert_policy' resource, set state = 'Enabled' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#state' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_030.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security should be enabled on your SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_sql_server', 'azurerm_mssql_server_security_alert_policy']


[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_alert_policy.rego
