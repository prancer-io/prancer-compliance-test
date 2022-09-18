



# Title: Ensure ActiveMQ engine version is approved by GS.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-MQ-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_12']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MQ-003|
|eval|data.rule.mq_activemq_approved_engine_version|
|message|data.rule.mq_activemq_approved_engine_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MQ_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is used to check only firm approved version of ActiveMQ is being used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS']|
|service|['mq']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
