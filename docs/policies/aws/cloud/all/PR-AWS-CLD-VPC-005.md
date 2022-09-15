



# Master Test ID: PR-AWS-CLD-VPC-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_05']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-VPC-005|
|eval|data.rule.vpc_peering_connection_inactive|
|message|data.rule.vpc_peering_connection_inactive_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_VPC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure VPC peering connection is not active.

***<font color="white">Description:</font>*** It checks of VPC peering is allowed between VPCs. VPC peering is not encrypted and not allowed to be used in GS environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['vpc']|



[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/vpc.rego
