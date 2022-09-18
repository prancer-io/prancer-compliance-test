



# Title: Ensure DocumentDB cluster is encrypted at rest


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DDB-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DDB-001|
|eval|data.rule.docdb_cluster_encrypt|
|message|data.rule.docdb_cluster_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DDB_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure that encryption is enabled for your AWS DocumentDB (with MongoDB compatibility) clusters for additional data security and in order to meet compliance requirements for data-at-rest encryption  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::docdb::dbcluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
