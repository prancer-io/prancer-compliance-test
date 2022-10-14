



# Title: Ensure General and Audit logs are published to CloudWatch.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-MQ-005

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-MQ-005|
|eval|data.rule.audit_logs_published_to_cloudWatch|
|message|data.rule.audit_logs_published_to_cloudWatch_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#aws-resource-amazonmq-broker--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_MQ_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::amazonmq::broker']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
