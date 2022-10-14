



# Title: Ensure AWS Glue security configuration encryption is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-GLUE-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-GLUE-002|
|eval|data.rule.glue_security_config|
|message|data.rule.glue_security_config_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_GLUE_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure AWS Glue security configuration encryption is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::glue::securityconfiguration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
