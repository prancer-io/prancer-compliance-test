



# Title: Azure Web Service http logging should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-007|
|eval|data.rule.web_service_http_logging_enabled|
|message|data.rule.web_service_http_logging_enabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_WEB_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure Web service which don't have http logging enabled and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
