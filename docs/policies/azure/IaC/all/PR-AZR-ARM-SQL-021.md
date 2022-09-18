



# Title: Threat Detection alert should be configured to send notifications to the SQL server account administrators


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-021

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbsecurityalertpolicies.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-021|
|eval|data.rule.sql_alert|
|message|data.rule.sql_alert_err|
|remediationDescription|In Resource of type "microsoft.sql/servers/databases/securityalertpolicies" make sure properties.emailAccountAdmins exist and its value set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_021.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that threat detection alert is configured to send notifications to the sql server account administrators  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers/databases']


[dbsecurityalertpolicies.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbsecurityalertpolicies.rego
