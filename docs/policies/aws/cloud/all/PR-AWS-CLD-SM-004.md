



# Master Test ID: PR-AWS-CLD-SM-004


Master Snapshot Id: ['TEST_ALL_02']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SM-004|
|eval: |data.rule.secret_manager_rotation_period|
|message: |data.rule.secret_manager_rotation_period_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.list_secrets' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SM_004.py|


severity: Low

title: Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).

description: It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['secret manager']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
