



# Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-VPC-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-VPC-002|
|eval|data.rule.eip_instance_link|
|message|data.rule.eip_instance_link_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_VPC_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['elastic IP']|



[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
