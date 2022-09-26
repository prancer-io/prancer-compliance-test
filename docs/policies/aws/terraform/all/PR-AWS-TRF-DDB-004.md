



# Title: Ensure DocDB has audit logs enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DDB-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DDB-004|
|eval|data.rule.docdb_parameter_group_audit_logs|
|message|data.rule.docdb_parameter_group_audit_logs_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster_parameter_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DDB_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure DocDB has audit logs enabled, this will export logs in docdb  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_docdb_cluster_parameter_group']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
