



# Title: Ensure AWS SNS topic is not exposed to unauthorized access.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SNS-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SNS-005|
|eval|data.rule.sns_not_unauthorized_access|
|message|data.rule.sns_not_unauthorized_access_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SNS_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It identifies AWS SNS topics that are exposed to unauthorized access. Amazon Simple Notification Service (Amazon SNS) is a web service that coordinates and manages the delivery or sending of messages to subscribing endpoints or clients. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM 2021', 'MAS TRM', 'Risk Management in Technology (RMiT)-10.55', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sns_topic_policy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego
