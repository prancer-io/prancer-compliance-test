



# Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-036

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-036|
|eval|data.rule.sql_server_email_addressess|
|message|data.rule.sql_server_email_addressess_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_036.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Databases']|



[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_alert_policy.rego
