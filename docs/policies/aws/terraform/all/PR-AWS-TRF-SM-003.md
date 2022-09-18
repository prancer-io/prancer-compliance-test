



# Title: Ensure AWS Secrets Manager automatic rotation is enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SM-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SM-003|
|eval|data.rule.secret_manager_automatic_rotation|
|message|data.rule.secret_manager_automatic_rotation_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SM_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Rotation is the process of periodically updating a secret. When you rotate a secret, you update the credentials in both the secret and the database or service. This control checks if automatic rotation for secrets is enabled in the secrets manager configuration.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_secretsmanager_secret_rotation', 'aws_secretsmanager_secret']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
