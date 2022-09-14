



# Master Test ID: PR-AZR-TRF-SQL-030


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(sql_alert_policy.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-030|
|eval: |data.rule.sql_server_alert|
|message: |data.rule.sql_server_alert_err|
|remediationDescription: |Make sure resource 'azurerm_sql_server' and 'azurerm_mssql_server_security_alert_policy' both exist and in 'azurerm_mssql_server_security_alert_policy' resource, set state = 'Enabled' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#state' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_030.py|


severity: Medium

title: Ensure Security Alert is enabled on Azure SQL Server

description: Advanced data security should be enabled on your SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_sql_server', 'azurerm_mssql_server_security_alert_policy']


[file(sql_alert_policy.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_alert_policy.rego
