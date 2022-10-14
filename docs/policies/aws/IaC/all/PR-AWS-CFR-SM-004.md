



# Title: Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SM-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SM-004|
|eval|data.rule.secret_manager_rotation_period|
|message|data.rule.secret_manager_rotation_period_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SM_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::secretsmanager::rotationschedule']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
