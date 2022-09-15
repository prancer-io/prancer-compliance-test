



# Master Test ID: PR-AWS-CLD-EC2-012


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-012|
|eval|data.rule.ebs_deletion_protection|
|message|data.rule.ebs_deletion_protection_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-volumes.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure EBS deletion protection is enabled

***<font color="white">Description:</font>*** This control checks if the EBS volumes provisioned is configured with deletion protection which protects from accidental deletions  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
