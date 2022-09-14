



# Master Test ID: PR-AZR-TRF-SQL-066


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(postgreSQL.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-066|
|eval: |data.rule.postgresql_public_access_disabled|
|message: |data.rule.postgresql_public_access_disabled_err|
|remediationDescription: |In 'azurerm_postgresql_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_066.py|


severity: High

title: Ensure PostgreSQL servers don't have public network access enabled

description: Always use Private Endpoint for PostgreSQL Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_postgresql_configuration', 'azurerm_postgresql_server', 'azurerm_postgresql_firewall_rule']


[file(postgreSQL.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
