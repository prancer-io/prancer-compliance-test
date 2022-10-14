



# Title: Ensure GCP Cloud Function HTTP trigger is secured


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CF-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLOUDFUNCTIONS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfunction.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CF-001|
|eval|data.rule.function_security|
|message|data.rule.function_security_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://github.com/GoogleCloudPlatform/storage-samples/tree/master/google/resource-snippets/cloudfunctions-v1' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CF_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud Functions for which the HTTP trigger is not secured. When you configure HTTP functions to be triggered only with HTTPS, user requests will be redirected to use the HTTPS protocol, which is more secure. It is recommended to set the 'Require HTTPS' for configuring HTTP triggers while deploying your function.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|[]|
|service|['cloud']|



[cloudfunction.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/cloudfunction.rego
