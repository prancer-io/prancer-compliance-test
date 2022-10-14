



# Title: Ensure Neptune logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-NPT-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-NPT-001|
|eval|data.rule.neptune_cluster_logs|
|message|data.rule.neptune_cluster_logs_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_NPT_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** These access logs can be used to analyze traffic patterns and troubleshoot security and operational issues.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_neptune_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
