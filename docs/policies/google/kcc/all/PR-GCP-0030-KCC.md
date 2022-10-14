



# Title: Shielded VM Disabled


***<font color="white">Master Test Id:</font>*** TEST_ComputeInstance_6

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0030-KCC|
|eval|data.rule.shielded_vm_disabled|
|message|data.rule.shielded_vm_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Shielded VM is disabled on this instance.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computeinstance']


[ComputeInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego
