



# Master Test ID: PR-AZR-TRF-SQL-069


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(sql_servers.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-069|
|eval: |data.rule.mssql_server_latest_tls_configured|
|message: |data.rule.mssql_server_latest_tls_configured_err|
|remediationDescription: |In 'azurerm_mssql_server' resource, set 'minimum_tls_version = 1.2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_069.py|


severity: High

title: Ensure Azure MSSQL Server has latest version of tls configured

description: This policy will identify the Azure MSSQL Server which dont have latest version of tls configured and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_mssql_server', 'azurerm_mssql_firewall_rule', 'azurerm_sql_server']


[file(sql_servers.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego
