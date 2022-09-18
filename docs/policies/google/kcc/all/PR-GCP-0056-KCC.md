



# Title: Auto Backup Disabled


***<font color="white">Master Test Id:</font>*** TEST_SQLInstance_1

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([SQLInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0056-KCC|
|eval|data.rule.auto_backup_disabled|
|message|data.rule.auto_backup_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A Cloud SQL database doesn't have automatic backups enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['sqlinstance']


[SQLInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego
