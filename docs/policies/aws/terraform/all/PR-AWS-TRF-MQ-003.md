



# Title: Ensure ActiveMQ engine version is approved by GS.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MQ-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MQ-003|
|eval|data.rule.mq_activemq_approved_engine_version|
|message|data.rule.mq_activemq_approved_engine_version_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MQ_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is used to check only firm approved version of ActiveMQ is being used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_mq_broker']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
