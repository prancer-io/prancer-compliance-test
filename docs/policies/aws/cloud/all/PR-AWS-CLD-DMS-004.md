



# Master Test ID: PR-AWS-CLD-DMS-004


***<font color="white">Master Snapshot Id:</font>*** ['TEST_DMS_02', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DMS-004|
|eval|data.rule.dms_gs_managed_key|
|message|data.rule.dms_gs_managed_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dms.html#DatabaseMigrationService.Client.describe_replication_instances' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DMS_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure DMS replication instance in encrypted by GS provided CMK.

***<font color="white">Description:</font>*** It checks if the default AWS Key is used for encryption. GS mandates CMK to be used for encryption.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['dms', 'kms']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
