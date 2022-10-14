



# Title: Ensure SQS queue policy is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-SQS-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_SQS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SQS-004|
|eval|data.rule.sqs_policy_public|
|message|data.rule.sqs_policy_public_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SQS_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Public SQS queues potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['HIPAA', 'PCI DSS', 'NIST 800', 'GDPR']|
|service|['sqs']|



[sqs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
