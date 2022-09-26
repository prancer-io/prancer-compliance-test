



# Title: Azure SQL Database Auditing Retention should be 90 days or more


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbauditingsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-006|
|eval|data.rule.sql_db_log_retention|
|message|data.rule.sql_db_log_retention_err|
|remediationDescription|To change the policy using the Azure Portal, follow these steps:<br><br>1. Log in to the Azure Portal at https://portal.azure.com.<br>2. Navigate to SQL Databases.<br>2. For each server instance:<br>a) Click Auditing.<br>b) Select Storage Details.<br>c) Set Retention (days) to greater than 90 days.<br>d) Click OK.<br>e) Click Save|
|remediationFunction|PR_AZR_CLD_SQL_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies SQL Databases that have Auditing Retention of fewer than 90 days. Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Databases']|



[dbauditingsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbauditingsettings.rego
