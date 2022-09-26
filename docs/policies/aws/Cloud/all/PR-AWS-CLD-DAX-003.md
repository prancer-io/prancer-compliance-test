



# Title: Ensure for AWS DAX GS-managed key is used in encryption.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-DAX-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_DAX', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DAX-003|
|eval|data.rule.dax_gs_managed_key|
|message|data.rule.dax_gs_managed_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dax.html#DAX.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DAX_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is to check that data at rest encryption has used firm managed CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['dax', 'kms']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
