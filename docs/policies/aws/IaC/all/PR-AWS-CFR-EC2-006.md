



# Title: Ensure AWS EC2 EBS and Network components' deletion protection is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EC2-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EC2-006|
|eval|data.rule.ec2_deletion_termination|
|message|data.rule.ec2_deletion_termination_err|
|remediationDescription|https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-template.html#cfn-ec2-blockdev-template-deleteontermination' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EC2_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This checks if the EBS volumes are configured to be terminated along with the EC2 instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego
