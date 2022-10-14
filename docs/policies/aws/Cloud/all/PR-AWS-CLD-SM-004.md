



# Title: Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-SM-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SM-004|
|eval|data.rule.secret_manager_rotation_period|
|message|data.rule.secret_manager_rotation_period_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.list_secrets' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SM_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['secret manager']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
