



# Master Test ID: PR-AWS-CLD-SNS-006


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SNS_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SNS-006|
|eval|data.rule.sns_permissive_for_publishing|
|message|data.rule.sns_permissive_for_publishing_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SNS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure AWS SNS topic policy is not overly permissive for publishing.

***<font color="white">Description:</font>*** It identifies AWS SNS topics that have SNS policy overly permissive for publishing. When a message is published, Amazon SNS attempts to deliver the message to the subscribed endpoints. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CIS AWS 3 Tier Web Architecture Benchmark v.1.0.0-2.9', 'CIS', 'MAS TRM 2021-9.1.1', 'MAS TRM', 'Risk Management in Technology (RMiT)-10.55', 'RMiT']|
|service|['sns']|



[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
