



# Title: Ensure detailed monitoring is enabled for EC2 instances


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC2-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC2-005|
|eval|data.rule.ec2_monitoring|
|message|data.rule.ec2_monitoring_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC2_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego
