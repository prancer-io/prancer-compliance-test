



# Master Test ID: PR-AWS-CLD-VPC-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-VPC-003|
|eval|data.rule.vpc_endpoint_manual_acceptance|
|message|data.rule.vpc_endpoint_manual_acceptance_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_VPC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure VPC endpoint service is configured for manual acceptance

***<font color="white">Description:</font>*** AcceptanceRequired Indicates whether requests from service consumers to create an endpoint to your service must be accepted, we recommend you to enable this feature  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['vpc']|



[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
