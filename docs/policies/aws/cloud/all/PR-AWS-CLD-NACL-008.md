



# Master Test ID: PR-AWS-CLD-NACL-008


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01NETWORKACL']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2networkacl.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-NACL-008|
|eval|data.rule.acl_no_rules_in_default_vpc|
|message|data.rule.acl_no_rules_in_default_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_acls' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_NACL_008.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure there are no rules in the Default VPC NACL.

***<font color="white">Description:</font>*** It checks if the default NACL is used for subnets, default NACL should not have any rules and not be attached to any subnets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CIS', 'Best Practice']|
|service|['nacl']|



[ec2networkacl.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2networkacl.rego
