



# Title: Ensure that EC2 instace is EBS Optimized


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC2-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-004|
|eval|data.rule.ec2_ebs_optimized|
|message|data.rule.ec2_ebs_optimized_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-ebsoptimized' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
