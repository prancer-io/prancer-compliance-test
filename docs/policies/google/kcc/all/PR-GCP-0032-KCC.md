



# Title: Default Network


***<font color="white">Master Test Id:</font>*** TEST_ComputeNetwork_1

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeNetwork.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0032-KCC|
|eval|data.rule.default_network|
|message|data.rule.default_network_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The default network exists in a project.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computenetwork']


[ComputeNetwork.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego
