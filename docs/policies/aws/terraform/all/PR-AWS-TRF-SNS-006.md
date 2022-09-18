



# Title: Ensure AWS SNS topic policy is not overly permissive for publishing.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SNS-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SNS-006|
|eval|data.rule.sns_permissive_for_publishing|
|message|data.rule.sns_permissive_for_publishing_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SNS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies AWS SNS topics that have SNS policy overly permissive for publishing. When a message is published, Amazon SNS attempts to deliver the message to the subscribed endpoints. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-2.9', 'CIS', 'MAS TRM 2021-9.1.1', 'MAS TRM', 'Risk Management in Technology (RMiT)-10.55', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sns_topic_policy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego
