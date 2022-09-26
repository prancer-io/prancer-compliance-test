



# Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-003|
|eval|data.rule.iam_wildcard_principal|
|message|data.rule.iam_wildcard_principal_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::role']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
