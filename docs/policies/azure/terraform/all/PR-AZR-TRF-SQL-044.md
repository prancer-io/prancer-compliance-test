



# Master Test ID: PR-AZR-TRF-SQL-044


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(dbserverauditingsettings.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-044|
|eval: |data.rule.mssql_log_retention|
|message: |data.rule.mssql_log_retention_err|
|remediationDescription: |In 'azurerm_mssql_server_extended_auditing_policy' resource, set the 'retention_in_days = 90' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy#retention_in_days' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_044.py|


severity: Medium

title: Azure MSSQL Server audit log retention should be equal or greater then 90 days

description: Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.<br><br>This policy identifies SQL servers which do not retain audit logs for 90 days or more. As a best practice, configure the audit logs retention time period to be equal or greater than 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_mssql_server_extended_auditing_policy', 'azurerm_mssql_server', 'azurerm_sql_server']


[file(dbserverauditingsettings.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbserverauditingsettings.rego
