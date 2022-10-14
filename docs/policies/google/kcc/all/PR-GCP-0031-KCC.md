



# Title: Org Policy Confidential VM Policy


***<font color="white">Master Test Id:</font>*** TEST_ComputeInstance_7

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0031-KCC|
|eval|data.rule.org_policy_confidential_vm_policy|
|message|data.rule.org_policy_confidential_vm_policy_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A Compute Engine resource is out of compliance with the constraints/compute.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computeinstance']


[ComputeInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego
