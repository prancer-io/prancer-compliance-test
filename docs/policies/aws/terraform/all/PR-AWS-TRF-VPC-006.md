



# Title: Ensure AWS VPC endpoint policy is not overly permissive.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-VPC-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-VPC-006|
|eval|data.rule.vpc_policy_not_overly_permissive|
|message|data.rule.vpc_policy_not_overly_permissive_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint#policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_VPC_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_vpc_endpoint']


[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego
