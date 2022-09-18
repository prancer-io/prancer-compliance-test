



# Title: Ensure AWS VPC endpoint policy is not overly permissive.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-VPC-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-VPC-006|
|eval|data.rule.vpc_policy_not_overly_permissive|
|message|data.rule.vpc_policy_not_overly_permissive_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpcendpointservice.html#cfn-ec2-vpcendpointservice-acceptancerequired' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_VPC_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::vpcendpoint']


[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego
