



# Title: Ensure DocDB has audit logs enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-DDB-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_DDB_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DDB-004|
|eval|data.rule.docdb_parameter_group_audit_logs|
|message|data.rule.docdb_parameter_group_audit_logs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#aws-resource-docdb-dbclusterparametergroup--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DDB_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure DocDB has audit logs enabled, this will export logs in docdb  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['docdb']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
