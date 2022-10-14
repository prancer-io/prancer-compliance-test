



# Title: Ensure Amazon MQ Broker logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MQ-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MQ-002|
|eval|data.rule.mq_logging_enable|
|message|data.rule.mq_logging_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MQ_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Amazon MQ is integrated with CloudTrail and provides a record of the Amazon MQ calls made by a user, role, or AWS service. It supports logging both the request parameters and the responses for APIs as events in CloudTrail  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_mq_broker']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
