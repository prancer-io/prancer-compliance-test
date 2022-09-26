



# Title: KMS Key Not Rotated


***<font color="white">Master Test Id:</font>*** TEST_KMSCryptoKey

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([KMSCryptoKey.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0055-KCC|
|eval|data.rule.kms_key_not_rotated|
|message|data.rule.kms_key_not_rotated_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Rotation isn't configured on a Cloud KMS encryption key.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['kmscryptokey']


[KMSCryptoKey.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/KMSCryptoKey.rego
