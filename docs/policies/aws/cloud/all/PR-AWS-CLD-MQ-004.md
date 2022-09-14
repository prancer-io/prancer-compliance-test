



# Master Test ID: PR-AWS-CLD-MQ-004


Master Snapshot Id: ['TEST_ALL_12']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MQ-004|
|eval: |data.rule.mq_rabbitmq_approved_engine_version|
|message: |data.rule.mq_rabbitmq_approved_engine_version_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MQ_004.py|


severity: Medium

title: Ensure RabbitMQ engine version is approved by GS.

description: It is used to check only firm approved version of RabbitMQ is being used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS']|
|service: |['mq']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
