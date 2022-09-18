



# Title: Threat Detection alert should be configured to sent notification to the sql server account administrators


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-021

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-021|
|eval|data.rule.mssql_alert|
|message|data.rule.mssql_alert_err|
|remediationDescription|In 'azurerm_mssql_server_security_alert_policy' resource, set 'email_account_admins = true' to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_account_admins' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_021.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that threat detection alert is configured to sent notification to the sql server account administrators  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mssql_server', 'azurerm_mssql_server_security_alert_policy']


[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbsecurityalertpolicies.rego
