



# Title: Activity log profile retention should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-MNT-010

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_501']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-MNT-010|
|eval|data.rule.log_profiles_retention_enabled|
|message|data.rule.log_profiles_retention_enabled_err|
|remediationDescription|To change the policy using the Azure Portal, follow these steps:<br><br>1. Log in to the Azure Portal at https://portal.azure.com.<br>2. Navigate to the Activity log.<br>3. Select Export.<br>4. Set Retention (days) to 365 or 0.<br>5. Click Save.|
|remediationFunction|PR_AZR_CLD_MNT_010.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Microsoft.Insights/logprofiles which don't have log retention enabled. Activity Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Management and governance']|



[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/activitylogalerts.rego
