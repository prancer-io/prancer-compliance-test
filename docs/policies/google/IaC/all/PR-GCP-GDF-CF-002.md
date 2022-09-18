



# Title: Ensure GCP Cloud Function is not configured with overly permissive Ingress setting


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CF-002

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfunction.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CF-002|
|eval|data.rule.function_ingress_allow_all|
|message|data.rule.function_ingress_allow_all_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CF_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud Functions that are configured with overly permissive Ingress setting. With overly permissive Ingress setting, all inbound requests to the function are allowed, from both the public and resources within the same project. It is recommended to restrict the traffic from the public and other resources, to get better network-based access control and allow traffic from VPC networks in the same project or traffic through the Cloud Load Balancer.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['cloudfunctions.v1.function', 'gcp-types/cloudfunctions-v1:projects.locations.functions']


[cloudfunction.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/cloudfunction.rego
