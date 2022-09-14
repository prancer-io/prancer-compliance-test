



# Master Test ID: PR-AZR-TRF-SQL-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(mysql_server.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-002|
|eval: |data.rule.mysql_server_uses_privatelink|
|message: |data.rule.mysql_server_uses_privatelink_err|
|remediationDescription: |'azurerm_mysql_server' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_mysql_server' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_002.py|


severity: Medium

title: MySQL server should use private link

description: Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your MySQL Server instances, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_mysql_server', 'azurerm_private_endpoint']


[file(mysql_server.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mysql_server.rego
