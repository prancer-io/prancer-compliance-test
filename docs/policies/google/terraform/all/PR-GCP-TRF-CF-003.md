



# Title: Ensure GCP Cloud Function is enabled with VPC connector


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CF-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudfunctions.v1.function.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CF-003|
|eval|data.rule.function_vpc_connector|
|message|data.rule.function_vpc_connector_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://github.com/GoogleCloudPlatform/deploymentmanager-samples/tree/master/google/resource-snippets/cloudfunctions-v1' target='_blank'>here</a>|
|remediationFunction|PR_GCP_TRF_CF_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud Functions that are not configured with a VPC connector. VPC connector helps function to connect to a resource inside a VPC in the same project. Setting up the VPC connector allows you to set up a secure perimeter to guard against data exfiltration and prevent functions from accidentally sending any data to unwanted destinations. It is recommended to configure the GCP Cloud Function with a VPC connector.

Note: For the Cloud Functions function to access the public traffic with Serverless VPC connector, you have to introduce Cloud NAT.
Link: https://cloud.google.com/functions/docs/networking/network-settings#route-egress-to-vpc  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_cloudfunctions_function']


[cloudfunctions.v1.function.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/cloudfunctions.v1.function.rego
