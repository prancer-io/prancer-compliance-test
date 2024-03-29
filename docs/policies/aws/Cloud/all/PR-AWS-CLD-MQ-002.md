



# Title: Ensure Amazon MQ Broker logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-MQ-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_12']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MQ-002|
|eval|data.rule.mq_logging_enable|
|message|data.rule.mq_logging_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MQ_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Amazon MQ is integrated with CloudTrail and provides a record of the Amazon MQ calls made by a user, role, or AWS service. It supports logging both the request parameters and the responses for APIs as events in CloudTrail  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS']|
|service|['mq']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
