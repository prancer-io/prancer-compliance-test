



# Title: Ensure no wildcards are specified in IAM policy with 'Action' section


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-002|
|eval|data.rule.iam_wildcard_action|
|message|data.rule.iam_wildcard_action_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CIS', 'NIST 800']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
