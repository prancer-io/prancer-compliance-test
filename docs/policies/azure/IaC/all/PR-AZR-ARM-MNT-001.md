



# Title: Activity log alerts settings should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([activitylogalerts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-001|
|eval|data.rule.alerts|
|message|data.rule.alerts_err|
|remediationDescription|Make sure you are following the ARM template guidelines for Activity Log Alert by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts' target='_blank'>here</a>|
|remediationFunction|PR_AZR_ARM_MNT_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Activity log alert rules are Azure resources, so they can be created by using an Azure Resource Manager template.   
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.insights/activitylogalerts']


[activitylogalerts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/activitylogalerts.rego
