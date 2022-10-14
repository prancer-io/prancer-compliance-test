



# Title: Ensure DocDB ParameterGroup has TLS enable


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DDB-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DDB-003|
|eval|data.rule.docdb_parameter_group_tls_enable|
|message|data.rule.docdb_parameter_group_tls_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster_parameter_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DDB_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** TLS can be used to encrypt the connection between an application and a DocDB cluster. By default, encryption in transit is enabled for newly created clusters. It can optionally be disabled when the cluster is created, or at a later time. When enabled, secure connections using TLS are required to connect to the cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_docdb_cluster_parameter_group']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
