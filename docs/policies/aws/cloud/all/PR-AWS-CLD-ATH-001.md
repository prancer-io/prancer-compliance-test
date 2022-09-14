



# Master Test ID: PR-AWS-CLD-ATH-001


Master Snapshot Id: ['TEST_ATH']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ATH-001|
|eval: |data.rule.athena_encryption_disabling_prevent|
|message: |data.rule.athena_encryption_disabling_prevent_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ATH_001.py|


severity: High

title: Ensure to enable EnforceWorkGroupConfiguration for athena workgroup

description: Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['athena']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
