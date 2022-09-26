



# Title: Ensure AWS DocumentDB logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DDB-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DDB-002|
|eval|data.rule.docdb_cluster_logs|
|message|data.rule.docdb_cluster_logs_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DDB_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_docdb_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
