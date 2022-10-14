



# Title: Ensure AWS Glue encrypt data at rest


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-GLUE-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-GLUE-003|
|eval|data.rule.glue_encrypt_data_at_rest|
|message|data.rule.glue_encrypt_data_at_rest_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_security_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_GLUE_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is to check that AWS Glue encryption at rest is enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_glue_security_configuration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
