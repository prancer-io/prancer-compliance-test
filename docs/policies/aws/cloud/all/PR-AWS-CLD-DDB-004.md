



# Master Test ID: PR-AWS-CLD-DDB-004


Master Snapshot Id: ['TEST_DDB_02']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DDB-004|
|eval: |data.rule.docdb_parameter_group_audit_logs|
|message: |data.rule.docdb_parameter_group_audit_logs_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#aws-resource-docdb-dbclusterparametergroup--examples' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DDB_004.py|


severity: Medium

title: Ensure DocDB has audit logs enabled

description: Ensure DocDB has audit logs enabled, this will export logs in docdb  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['docdb']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
