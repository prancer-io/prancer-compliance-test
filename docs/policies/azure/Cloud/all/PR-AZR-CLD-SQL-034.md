



# Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-034

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-034|
|eval|data.rule.sql_server_email_account|
|message|data.rule.sql_server_email_account_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies?tabs=json' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_034.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Databases']|



[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_alert_policy.rego
