



# Title: AWS IAM policy is overly permissive to all traffic via condition clause


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-006|
|eval|data.rule.iam_all_traffic|
|message|data.rule.iam_all_traffic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
