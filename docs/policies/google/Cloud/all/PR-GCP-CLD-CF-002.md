



# Title: Ensure GCP Cloud Function is not configured with overly permissive Ingress setting


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CF-002

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLOUDFUNCTIONS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfunction.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CF-002|
|eval|data.rule.function_ingress_allow_all|
|message|data.rule.function_ingress_allow_all_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://github.com/GoogleCloudPlatform/storage-samples/tree/master/google/resource-snippets/cloudfunctions-v1' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CF_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud Functions that are configured with overly permissive Ingress setting. With overly permissive Ingress setting, all inbound requests to the function are allowed, from both the public and resources within the same project. It is recommended to restrict the traffic from the public and other resources, to get better network-based access control and allow traffic from VPC networks in the same project or traffic through the Cloud Load Balancer.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|[]|
|service|['cloud']|



[cloudfunction.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/cloudfunction.rego
