



# Title: Public IP Address


***<font color="white">Master Test Id:</font>*** TEST_ComputeInstance_5

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0029-KCC|
|eval|data.rule.public_ip_address|
|message|data.rule.public_ip_address_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** An instance has a public IP address.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computeinstance']


[ComputeInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego
