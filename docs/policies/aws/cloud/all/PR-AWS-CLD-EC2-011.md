



# Master Test ID: PR-AWS-CLD-EC2-011


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-011|
|eval|data.rule.ebs_volume_attached|
|message|data.rule.ebs_volume_attached_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-volumes.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_011.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure EBS volume is attached

***<font color="white">Description:</font>*** This control check if EBS snapshots are encrypted at-rest. Snapshots of EBS volumes should be encrypted to avoid misuse. Encryption can be enabled at the account level for EBS volumes and snapshots  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
