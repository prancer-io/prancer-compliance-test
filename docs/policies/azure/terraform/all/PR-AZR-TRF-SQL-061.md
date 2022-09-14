



# Master Test ID: PR-AZR-TRF-SQL-061


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(mysql_server.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-061|
|eval: |data.rule.mysql_server_latest_tls_configured|
|message: |data.rule.mysql_server_latest_tls_configured_err|
|remediationDescription: |In 'azurerm_mysql_server' resource, set ssl_minimal_tls_version_enforced = 'TLS1_2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_061.py|


severity: Medium

title: Ensure Azure MySQL Server has latest version of tls configured

description: This policy will identify the Azure MySQL Server which dont have latest version of tls configured and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_mysql_firewall_rule', 'azurerm_mysql_server']


[file(mysql_server.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mysql_server.rego
