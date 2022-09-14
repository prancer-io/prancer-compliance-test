



# Master Test ID: PR-AWS-CLD-VPC-004


Master Snapshot Id: ['TEST_EC2_04']

type: rego

rule: [file(vpc.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-VPC-004|
|eval: |data.rule.default_vpc_not_used|
|message: |data.rule.default_vpc_not_used_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_VPC_004.py|


severity: Medium

title: Ensure default VPC is not being used.

description: It is to check that only firm managed VPC is used and not the default one.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['vpc']|



[file(vpc.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
