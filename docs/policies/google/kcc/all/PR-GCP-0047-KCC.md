



# Title: COS Not Used


***<font color="white">Master Test Id:</font>*** TEST_ContainerNodePool_3

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerNodePool.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0047-KCC|
|eval|data.rule.cos_not_used|
|message|data.rule.cos_not_used_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containernodepool']


[ContainerNodePool.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego
