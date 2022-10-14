



# Title: Ensure enhanaced monitoring for AWS MSK is not set to default.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MSK-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MSK-006|
|eval|data.rule.msk_cluster_enhanced_monitoring_enable|
|message|data.rule.msk_cluster_enhanced_monitoring_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#example-usage' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MSK_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is used to check that enhanced monitoring is configured to gather Apache Kafka metrics and sends them to Amazon CloudWatch.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_msk_cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/msk.rego
