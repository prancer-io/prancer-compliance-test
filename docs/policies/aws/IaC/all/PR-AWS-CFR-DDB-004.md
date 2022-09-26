



# Title: Ensure DocDB has audit logs enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DDB-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DDB-004|
|eval|data.rule.docdb_parameter_group_audit_logs|
|message|data.rule.docdb_parameter_group_audit_logs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#aws-resource-docdb-dbclusterparametergroup--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DDB_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure DocDB has audit logs enabled, this will export logs in docdb  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::docdb::dbclusterparametergroup']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
