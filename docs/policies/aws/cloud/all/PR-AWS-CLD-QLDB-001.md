



# Master Test ID: PR-AWS-CLD-QLDB-001


Master Snapshot Id: ['TEST_QLDB']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-QLDB-001|
|eval: |data.rule.qldb_permission_mode|
|message: |data.rule.qldb_permission_mode_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_QLDB_001.py|


severity: Medium

title: Ensure QLDB ledger permissions mode is set to STANDARD

description: In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['docdb']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
