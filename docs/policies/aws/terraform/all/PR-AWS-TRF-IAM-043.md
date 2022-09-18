



# Title: Ensure IAM policy is not overly permissive to all traffic via condition clause.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-043

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-043|
|eval|data.rule.iam_policy_not_overly_permissive_to_all_traffic|
|message|data.rule.iam_policy_not_overly_permissive_to_all_traffic_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_043.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'RMiT', 'Risk Management in Technology (RMiT)-10.55', 'Risk Management in Technology (RMiT)-10.68']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
