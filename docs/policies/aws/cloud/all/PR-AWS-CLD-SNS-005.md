



# Master Test ID: PR-AWS-CLD-SNS-005


Master Snapshot Id: ['TEST_SNS_02']

type: rego

rule: [file(sns.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SNS-005|
|eval: |data.rule.sns_not_unauthorized_access|
|message: |data.rule.sns_not_unauthorized_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SNS_005.py|


severity: High

title: Ensure AWS SNS topic is not exposed to unauthorized access.

description: It identifies AWS SNS topics that are exposed to unauthorized access. Amazon Simple Notification Service (Amazon SNS) is a web service that coordinates and manages the delivery or sending of messages to subscribing endpoints or clients. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['MAS TRM 2021', 'MAS TRM', 'Risk Management in Technology (RMiT)-10.55', 'RMiT']|
|service: |['sns']|



[file(sns.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
