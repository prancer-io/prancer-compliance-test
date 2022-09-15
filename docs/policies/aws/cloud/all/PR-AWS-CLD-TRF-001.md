



# Master Test ID: PR-AWS-CLD-TRF-001


***<font color="white">Master Snapshot Id:</font>*** ['TEST_TRF']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-TRF-001|
|eval|data.rule.transer_server_public_expose|
|message|data.rule.transer_server_public_expose_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointdetails' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_TRF_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Transfer Server is not publicly exposed

***<font color="white">Description:</font>*** It is recommended that you use VPC as the EndpointType. With this endpoint type, you have the option to directly associate up to three Elastic IPv4 addresses (BYO IP included) with your server's endpoint and use VPC security groups to restrict traffic by the client's public IP address. This is not possible with EndpointType set to VPC_ENDPOINT.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['emr']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
