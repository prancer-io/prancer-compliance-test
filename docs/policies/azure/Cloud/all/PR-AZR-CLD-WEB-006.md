



# Title: Ensure CORS configuration is not allowing every resources to access Azure Web Service


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-006|
|eval|data.rule.web_service_cors_not_allowing_all|
|message|data.rule.web_service_cors_not_allowing_all_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/rest/api/storageservices/cross-origin-resource-sharing--cors--support-for-the-azure-storage-services' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_WEB_006.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify CORS configuration which are allowing every resoruce to access Azure Web service and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
