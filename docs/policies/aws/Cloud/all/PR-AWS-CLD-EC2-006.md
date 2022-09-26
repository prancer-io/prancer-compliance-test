



# Title: Ensure AWS EC2 EBS and Network components' deletion protection is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC2-006

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-006|
|eval|data.rule.ec2_deletion_termination|
|message|data.rule.ec2_deletion_termination_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This checks if the EBS volumes are configured to be terminated along with the EC2 instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
