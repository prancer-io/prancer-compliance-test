



# Master Test ID: PR-AWS-CLD-VPC-006


Master Snapshot Id: ['TEST_EC2_06']

type: rego

rule: [file(vpc.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-VPC-006|
|eval: |data.rule.vpc_policy_not_overly_permissive|
|message: |data.rule.vpc_policy_not_overly_permissive_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_VPC_006.py|


severity: Medium

title: Ensure AWS VPC endpoint policy is not overly permissive.

description: It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['vpc']|



[file(vpc.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
