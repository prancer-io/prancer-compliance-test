



# Title: Ensure AWS Glue encrypt data at rest


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-GLUE-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-GLUE-003|
|eval|data.rule.glue_encrypt_data_at_rest|
|message|data.rule.glue_encrypt_data_at_rest_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_GLUE_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is to check that AWS Glue encryption at rest is enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::glue::securityconfiguration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
