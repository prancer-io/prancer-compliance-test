



# Title: AWS SQS does not have a dead letter queue configured


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SQS-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SQS-001|
|eval|data.rule.sqs_deadletter|
|message|data.rule.sqs_deadletter_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SQS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sqs_queue']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sqs.rego
