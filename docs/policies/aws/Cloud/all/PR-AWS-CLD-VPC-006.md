



# Title: Ensure AWS VPC endpoint policy is not overly permissive.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-VPC-006

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_06']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-VPC-006|
|eval|data.rule.vpc_policy_not_overly_permissive|
|message|data.rule.vpc_policy_not_overly_permissive_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_VPC_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['vpc']|



[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
