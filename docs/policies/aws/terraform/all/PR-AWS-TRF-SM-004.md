



# Title: Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SM-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SM-004|
|eval|data.rule.secret_manager_rotation_period|
|message|data.rule.secret_manager_rotation_period_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation#automatically_after_days' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SM_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_secretsmanager_secret_rotation']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
