



# Title: Azure Web Service http logging should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-WEB-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-WEB-007|
|eval|data.rule.web_service_http_logging_enabled|
|message|data.rule.web_service_http_logging_enabled_err|
|remediationDescription|In 'microsoft.web/sites' resource, make sure 'httpLoggingEnabled' exists and the value is set to true.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_WEB_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure Web service which don't have http logging enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.web/sites']


[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/web.rego
