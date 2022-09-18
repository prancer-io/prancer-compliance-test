



# Title: Azure Web Service request tracing should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-WEB-009

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-WEB-009|
|eval|data.rule.web_service_request_tracing_enabled|
|message|data.rule.web_service_request_tracing_enabled_err|
|remediationDescription|make sure 'requestTracingEnabled' exists and the value is set to true.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_WEB_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure web service which doesn't have request tracing enabled and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.web/sites']


[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/web.rego
