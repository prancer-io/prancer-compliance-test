



# Master Test ID: PR-AWS-CLD-GLUE-001


Master Snapshot Id: ['TEST_ALL_05']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-GLUE-001|
|eval: |data.rule.glue_catalog_encryption|
|message: |data.rule.glue_catalog_encryption_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_GLUE_001.py|


severity: High

title: Ensure Glue Data Catalog encryption is enabled

description: Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HIPAA', 'NIST 800', 'GDPR']|
|service: |['glue']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
