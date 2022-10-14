



# Title: Ensure that EC2 instace is EBS Optimized


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC2-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC2-004|
|eval|data.rule.ec2_ebs_optimized|
|message|data.rule.ec2_ebs_optimized_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC2_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego
