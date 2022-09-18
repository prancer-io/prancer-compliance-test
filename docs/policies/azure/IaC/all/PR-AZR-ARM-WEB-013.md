



# Title: Azure Web Service Dot Net Framework should be latest


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-WEB-013

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-WEB-013|
|eval|data.rule.web_service_net_framework_latest|
|message|data.rule.web_service_net_framework_latest_err|
|remediationDescription|In 'microsoft.web/sites' resource, set netFrameworkVersion = 'v6.0' under 'siteConfig' block to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_WEB_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure web service which doesn't have the latest version of Net Framework and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.web/sites']


[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/web.rego
