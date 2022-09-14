



# Master Test ID: PR-AWS-CLD-SQS-003


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-003|
|eval: |data.rule.sqs_encrypt|
|message: |data.rule.sqs_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_003.py|


severity: High

title: AWS SQS server side encryption not enabled

description: SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HIPAA', 'PCI DSS', 'NIST 800', 'GDPR']|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
