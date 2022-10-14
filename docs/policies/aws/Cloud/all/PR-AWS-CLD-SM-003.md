



# Title: Ensure AWS Secrets Manager automatic rotation is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-SM-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SM-003|
|eval|data.rule.secret_manager_automatic_rotation|
|message|data.rule.secret_manager_automatic_rotation_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.list_secrets' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SM_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Rotation is the process of periodically updating a secret. When you rotate a secret, you update the credentials in both the secret and the database or service. This control checks if automatic rotation for secrets is enabled in the secrets manager configuration.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['secret manager']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
