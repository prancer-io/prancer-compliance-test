



# Title: Ensure General and Audit logs are published to CloudWatch.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MQ-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MQ-005|
|eval|data.rule.audit_logs_published_to_cloudWatch|
|message|data.rule.audit_logs_published_to_cloudWatch_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MQ_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_mq_broker']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
