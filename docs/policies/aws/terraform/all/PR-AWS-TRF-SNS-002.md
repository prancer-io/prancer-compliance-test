



# Title: AWS SNS topic encrypted using default KMS key instead of CMK


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SNS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SNS-002|
|eval|data.rule.sns_encrypt_key|
|message|data.rule.sns_encrypt_key_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SNS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sns_topic']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego
