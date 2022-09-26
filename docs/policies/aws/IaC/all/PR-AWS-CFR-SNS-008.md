



# Title: Ensure AWS SNS topic do not have cross-account access.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SNS-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SNS-008|
|eval|data.rule.sns_cross_account_access|
|message|data.rule.sns_cross_account_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SNS_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It identifies AWS SNS topics that are configured with cross-account access. Allowing unknown cross-account access to your SNS topics will enable other accounts and gain control over your AWS SNS topics. To prevent unknown cross-account access, allow only trusted entities to access your Amazon SNS topics by implementing the appropriate SNS policies.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM 2021', 'MAS TRM', 'Risk Management in Technology (RMiT)-10.55', 'RMiT']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sns::topicpolicy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego
