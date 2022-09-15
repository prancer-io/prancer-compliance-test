



# Master Test ID: PR-AWS-CLD-EC2-005


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-005|
|eval|data.rule.ec2_monitoring|
|message|data.rule.ec2_monitoring_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-monitoring' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure detailed monitoring is enabled for EC2 instances

***<font color="white">Description:</font>*** Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
