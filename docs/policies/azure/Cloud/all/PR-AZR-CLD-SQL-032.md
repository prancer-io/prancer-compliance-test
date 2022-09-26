



# Title: Advanced data security should be enabled on your SQL managed instance.


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-032

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_401']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_alert_policy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-032|
|eval|data.rule.sql_managed_instance_alert|
|message|data.rule.sql_managed_instance_alert_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/threat-detection-configure' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security should be enabled on your SQL managed instance.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Databases']|



[sql_alert_policy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/sql_alert_policy.rego
