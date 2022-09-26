



# Title: Auto Repair Disabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerNodePool_1

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerNodePool.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0045-KCC|
|eval|data.rule.auto_repair_disabled|
|message|data.rule.auto_repair_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A GKE cluster's auto repair feature, which keeps nodes in a healthy, running state, is disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containernodepool']


[ContainerNodePool.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego
