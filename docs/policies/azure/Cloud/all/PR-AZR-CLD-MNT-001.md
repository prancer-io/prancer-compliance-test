



# Title: Activity log alerts settings should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-MNT-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_299']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-MNT-001|
|eval|data.rule.alerts|
|message|data.rule.alerts_err|
|remediationDescription|Follow the guideline mentioned <a href='' target=https://docs.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts'_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_MNT_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Activity log alert rules are Azure resources, so they can be created by using an Azure Resource Manager template.   
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Management and governance']|



[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/activitylogalerts.rego
