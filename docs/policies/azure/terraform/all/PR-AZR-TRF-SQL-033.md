



# Master Test ID: PR-AZR-TRF-SQL-033


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(sql_servers.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-033|
|eval: |data.rule.sql_public_access_disabled|
|message: |data.rule.sql_public_access_disabled_err|
|remediationDescription: |In 'azurerm_sql_server' resource, set 'public_network_access_enabled = false' to fix the issue. If 'public_network_access_enabled' property does not exist please add it. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#public_network_access_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_033.py|


severity: High

title: Ensure SQL servers don't have public network access enabled

description: Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_sql_server', 'azurerm_private_endpoint']


[file(sql_servers.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego
