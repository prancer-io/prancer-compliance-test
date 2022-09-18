



# Title: Disk CMEK Disabled


***<font color="white">Master Test Id:</font>*** TEST_ComputeDisk

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeDisk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0001-KCC|
|eval|data.rule.disk_cmek_disabled|
|message|data.rule.disk_cmek_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disks on this VM are not encrypted with CMEK or CSEC.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computedisk']


[ComputeDisk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego
