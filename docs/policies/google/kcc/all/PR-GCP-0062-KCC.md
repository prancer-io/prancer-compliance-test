



# Title: Locked Retention Policy Not Set


***<font color="white">Master Test Id:</font>*** TEST_StorageBucket_4

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([StorageBucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0062-KCC|
|eval|data.rule.locked_retention_policy_not_set|
|message|data.rule.locked_retention_policy_not_set_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A locked retention policy is not set for logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['storagebucket']


[StorageBucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego
