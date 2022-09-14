



# Master Test ID: PR-AZR-TRF-SQL-015


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(dbsecurityalertpolicies.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-015|
|eval: |data.rule.sql_alert|
|message: |data.rule.sql_alert_err|
|remediationDescription: |In 'azurerm_mssql_server_security_alert_policy' resource, set 'email_account_admins = true' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_account_admins' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_015.py|


severity: Medium

title: Threat Detection alert should be configured to sent notification to the sql server account administrators

description: Ensure that threat detection alert is configured to sent notification to the sql server account administrators  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_sql_server', 'azurerm_mssql_server_security_alert_policy']


[file(dbsecurityalertpolicies.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbsecurityalertpolicies.rego
