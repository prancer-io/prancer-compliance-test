



# Title: Sql No Root Password


***<font color="white">Master Test Id:</font>*** TEST_SQLInstance_3

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([SQLInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0058-KCC|
|eval|data.rule.sql_no_root_password|
|message|data.rule.sql_no_root_password_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A Cloud SQL database doesn't have a password configured for the root account.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['sqlinstance']


[SQLInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego
