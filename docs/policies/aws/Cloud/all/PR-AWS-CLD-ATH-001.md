



# Title: Ensure to enable EnforceWorkGroupConfiguration for athena workgroup


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ATH-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ATH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ATH-001|
|eval|data.rule.athena_encryption_disabling_prevent|
|message|data.rule.athena_encryption_disabling_prevent_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ATH_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['athena']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
