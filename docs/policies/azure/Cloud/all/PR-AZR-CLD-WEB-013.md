



# Title: Azure Web Service Dot Net Framework should be latest


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-013

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-013|
|eval|data.rule.web_service_net_framework_latest|
|message|data.rule.web_service_net_framework_latest_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/app-service/configure-language-dotnet-framework' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_WEB_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure web service which doesn't have the latest version of Net Framework and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
