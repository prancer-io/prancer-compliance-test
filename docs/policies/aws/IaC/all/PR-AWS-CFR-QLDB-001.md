



# Title: Ensure QLDB ledger permissions mode is set to STANDARD


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-QLDB-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-QLDB-001|
|eval|data.rule.qldb_permission_mode|
|message|data.rule.qldb_permission_mode_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_QLDB_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::qldb::ledger']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
