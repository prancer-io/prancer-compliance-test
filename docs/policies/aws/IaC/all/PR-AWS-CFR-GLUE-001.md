



# Title: Ensure Glue Data Catalog encryption is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-GLUE-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-GLUE-001|
|eval|data.rule.glue_catalog_encryption|
|message|data.rule.glue_catalog_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_GLUE_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::glue::datacatalogencryptionsettings']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
