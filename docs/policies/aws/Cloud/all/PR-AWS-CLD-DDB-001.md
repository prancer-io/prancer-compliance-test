



# Title: Ensure DocumentDB cluster is encrypted at rest


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-DDB-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_DDB_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DDB-001|
|eval|data.rule.docdb_cluster_encrypt|
|message|data.rule.docdb_cluster_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DDB_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that encryption is enabled for your AWS DocumentDB (with MongoDB compatibility) clusters for additional data security and in order to meet compliance requirements for data-at-rest encryption  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['docdb']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
