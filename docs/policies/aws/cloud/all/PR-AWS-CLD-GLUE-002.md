



# Master Test ID: PR-AWS-CLD-GLUE-002


Master Snapshot Id: ['TEST_ALL_06']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-GLUE-002|
|eval: |data.rule.glue_security_config|
|message: |data.rule.glue_security_config_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_GLUE_002.py|


severity: Medium

title: Ensure AWS Glue security configuration encryption is enabled

description: Ensure AWS Glue security configuration encryption is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['glue']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
