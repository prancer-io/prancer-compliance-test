



# Title: Ensure GCP KMS encryption key rotating in every 90 days


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-KMS-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([kms.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-KMS-001|
|eval|data.rule.kms_key_rotation|
|message|data.rule.kms_key_rotation_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP KMS encryption keys that are not rotating every 90 days.  A key is used to protect some corpus of data. A collection of files could be encrypted with the same key and people with decrypt permissions on that key would be able to decrypt those files. It's recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old key.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_kms_key']


[kms.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/kms.rego
