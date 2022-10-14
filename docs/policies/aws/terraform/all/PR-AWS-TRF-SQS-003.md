



# Title: AWS SQS server side encryption not enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SQS-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SQS-003|
|eval|data.rule.sqs_encrypt|
|message|data.rule.sqs_encrypt_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SQS_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer.<br><br>SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sqs_queue']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sqs.rego
