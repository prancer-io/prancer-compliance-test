



# Title: Compute Serial Ports Enabled


***<font color="white">Master Test Id:</font>*** TEST_ComputeInstance_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0026-KCC|
|eval|data.rule.compute_serial_ports_enabled|
|message|data.rule.compute_serial_ports_enabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Serial ports are enabled for an instance, allowing connections to the instance's serial console.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computeinstance']


[ComputeInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego
