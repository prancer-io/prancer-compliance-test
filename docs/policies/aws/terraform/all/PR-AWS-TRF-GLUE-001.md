



# Title: Ensure Glue Data Catalog encryption is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-GLUE-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-GLUE-001|
|eval|data.rule.glue_catalog_encryption|
|message|data.rule.glue_catalog_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_data_catalog_encryption_settings' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_GLUE_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'NIST 800', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_glue_data_catalog_encryption_settings']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
