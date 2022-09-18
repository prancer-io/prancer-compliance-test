



# Title: AWS CodeDeploy application compute platform must be ECS or Lambda


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CD-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([code.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CD-001|
|eval|data.rule.deploy_compute_platform|
|message|data.rule.deploy_compute_platform_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codedeploy_app' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CD_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** AWS CodeDeploy application compute platform must be ECS or Lambda  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['SOC 2', 'PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_codedeploy_app']


[code.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/code.rego
