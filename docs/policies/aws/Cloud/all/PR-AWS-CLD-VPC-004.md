



# Title: Ensure default VPC is not being used.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-VPC-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_04']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-VPC-004|
|eval|data.rule.default_vpc_not_used|
|message|data.rule.default_vpc_not_used_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_VPC_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is to check that only firm managed VPC is used and not the default one.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['vpc']|



[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
