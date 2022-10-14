



# Title: IAM Roles should not have names that start with "cdk" or "cft".


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-010

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-010|
|eval|data.rule.iam_role_name_check|
|message|data.rule.iam_role_name_check_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_010.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** IAM Roles should not have RoleNames that match protected namespaces "cdk" or "cft".  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::role']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
