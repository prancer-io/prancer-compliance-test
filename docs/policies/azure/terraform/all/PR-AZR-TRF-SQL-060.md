



# Master Test ID: PR-AZR-TRF-SQL-060


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(mysql_server.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-060|
|eval: |data.rule.mysql_public_access_disabled|
|message: |data.rule.mysql_public_access_disabled_err|
|remediationDescription: |In 'azurerm_mysql_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_060.py|


severity: High

title: Ensure MySQL servers don't have public network access enabled

description: Always use Private Endpoint for Azure MySQL Database Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_mysql_firewall_rule', 'azurerm_mysql_server']


[file(mysql_server.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mysql_server.rego
