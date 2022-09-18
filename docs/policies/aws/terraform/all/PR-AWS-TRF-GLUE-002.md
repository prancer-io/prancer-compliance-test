



# Title: Ensure AWS Glue security configuration encryption is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-GLUE-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-GLUE-002|
|eval|data.rule.glue_security_config|
|message|data.rule.glue_security_config_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_security_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_GLUE_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure AWS Glue security configuration encryption is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_glue_security_configuration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
