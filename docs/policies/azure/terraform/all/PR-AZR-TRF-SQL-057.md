



# Master Test ID: PR-AZR-TRF-SQL-057


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(mariadb.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-057|
|eval: |data.rule.mairadb_public_access_disabled|
|message: |data.rule.mairadb_public_access_disabled_err|
|remediationDescription: |In 'azurerm_mariadb_server' resource, set 'public_network_access_enabled = false' or make sure resource 'azurerm_private_endpoint' exist to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_057.py|


severity: High

title: Ensure MariaDB servers don't have public network access enabled

description: Always use Private Endpoint for MariaDB Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_mariadb_firewall_rule', 'azurerm_mariadb_server']


[file(mariadb.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
