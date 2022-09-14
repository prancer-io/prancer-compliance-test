



# Master Test ID: PR-AWS-CLD-SQS-001


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-001|
|eval: |data.rule.sqs_deadletter|
|message: |data.rule.sqs_deadletter_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_001.py|


severity: Medium

title: AWS SQS does not have a dead letter queue configured

description: This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HIPAA', 'PCI DSS', 'NIST 800', 'GDPR']|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
