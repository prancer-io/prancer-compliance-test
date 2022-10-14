



# Title: AWS SQS server side encryption not enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SQS-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SQS-003|
|eval|data.rule.sqs_encrypt|
|message|data.rule.sqs_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SQS_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sqs::queue']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego
