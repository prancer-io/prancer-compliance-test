



# Title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-004|
|eval|data.rule.iam_resource_format|
|message|data.rule.iam_resource_format_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_004.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::user', 'aws::iam::group', 'aws::iam::role']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
