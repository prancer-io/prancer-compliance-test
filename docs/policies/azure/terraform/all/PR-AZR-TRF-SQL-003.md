



# Master Test ID: PR-AZR-TRF-SQL-003


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(postgreSQL.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-003|
|eval: |data.rule.pgsql_server_uses_privatelink|
|message: |data.rule.pgsql_server_uses_privatelink_err|
|remediationDescription: |'azurerm_postgresql_server' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_postgresql_server' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_003.py|


severity: Medium

title: PostgreSQL servers should use private link

description: Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your PostgreSQL servers instances, data leakage risks are reduced.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_postgresql_server', 'azurerm_private_endpoint']


[file(postgreSQL.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
