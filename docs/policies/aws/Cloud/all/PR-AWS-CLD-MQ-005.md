



# Title: Ensure General and Audit logs are published to CloudWatch.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-MQ-005

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_12']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MQ-005|
|eval|data.rule.audit_logs_published_to_cloudWatch|
|message|data.rule.audit_logs_published_to_cloudWatch_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MQ_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS']|
|service|['mq']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
