



# Title: Bucket CMEK Disabled


***<font color="white">Master Test Id:</font>*** TEST_StorageBucket_1

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([StorageBucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0059-KCC|
|eval|data.rule.bucket_cmek_disabled|
|message|data.rule.bucket_cmek_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A bucket is not encrypted with customer-managed encryption keys (CMEK).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['storagebucket']


[StorageBucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego
