



# Title: Ensure DocDB ParameterGroup has TLS enable


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DDB-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DDB-003|
|eval|data.rule.docdb_parameter_group_tls_enable|
|message|data.rule.docdb_parameter_group_tls_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-parameters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DDB_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** TLS can be used to encrypt the connection between an application and a DocDB cluster. By default, encryption in transit is enabled for newly created clusters. It can optionally be disabled when the cluster is created, or at a later time. When enabled, secure connections using TLS are required to connect to the cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::docdb::dbclusterparametergroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
