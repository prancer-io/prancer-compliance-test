



# Title: Ensure that Secrets Manager secret is encrypted using KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SM-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SM-001|
|eval|data.rule.secret_manager_kms|
|message|data.rule.secret_manager_kms_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SM_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::secretsmanager::secret']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
