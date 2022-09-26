



# Title: Ensure GCP Cloud Function HTTP trigger is secured


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CF-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfunction.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CF-001|
|eval|data.rule.function_security|
|message|data.rule.function_security_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CF_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud Functions for which the HTTP trigger is not secured. When you configure HTTP functions to be triggered only with HTTPS, user requests will be redirected to use the HTTPS protocol, which is more secure. It is recommended to set the 'Require HTTPS' for configuring HTTP triggers while deploying your function.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['cloudfunctions.v1.function', 'gcp-types/cloudfunctions-v1:projects.locations.functions']


[cloudfunction.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/cloudfunction.rego
