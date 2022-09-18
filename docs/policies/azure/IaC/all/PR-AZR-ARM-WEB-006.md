



# Title: Ensure CORS configuration is not allowing every resource to access Azure Web Service


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-WEB-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-WEB-006|
|eval|data.rule.web_service_cors_not_allowing_all|
|message|data.rule.web_service_cors_not_allowing_all_err|
|remediationDescription|In 'microsoft.web/sites' resource, don't set '*' as value to 'allowedOrigins' under 'cors' block which exists under 'siteConfig' block to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_WEB_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify CORS configuration which are allowing every resoruces to access Azure Web service and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.web/sites']


[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/web.rego
