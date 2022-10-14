



# Title: Ensure SQS queue policy is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SQS-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SQS-004|
|eval|data.rule.sqs_policy_public|
|message|data.rule.sqs_policy_public_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SQS_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Public SQS queues potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sqs_queue_policy']


[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sqs.rego
