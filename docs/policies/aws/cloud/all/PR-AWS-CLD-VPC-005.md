



# Master Test ID: PR-AWS-CLD-VPC-005


Master Snapshot Id: ['TEST_EC2_05']

type: rego

rule: [file(vpc.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-VPC-005|
|eval: |data.rule.vpc_peering_connection_inactive|
|message: |data.rule.vpc_peering_connection_inactive_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_VPC_005.py|


severity: Medium

title: Ensure VPC peering connection is not active.

description: It checks of VPC peering is allowed between VPCs. VPC peering is not encrypted and not allowed to be used in GS environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['vpc']|



[file(vpc.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
