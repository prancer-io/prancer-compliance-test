



# Title: Ensure that Secrets Manager secret is encrypted using KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SM-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SM-001|
|eval|data.rule.secret_manager_kms|
|message|data.rule.secret_manager_kms_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SM_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_secretsmanager_secret']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
