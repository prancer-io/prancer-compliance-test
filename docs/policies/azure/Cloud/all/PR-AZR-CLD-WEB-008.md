



# Title: Azure Web Service detailed error message should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-008

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-008|
|eval|data.rule.web_service_detaild_error_message_enabled|
|message|data.rule.web_service_detaild_error_message_enabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_WEB_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure Web service which doesn't have a detailed error message enabled and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
