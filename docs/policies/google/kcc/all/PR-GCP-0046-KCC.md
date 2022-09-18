



# Title: Auto Upgrade Disabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerNodePool_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerNodePool.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0046-KCC|
|eval|data.rule.auto_upgrade_disabled|
|message|data.rule.auto_upgrade_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A GKE cluster's auto upgrade feature, which keeps clusters and node pools on the latest stable version of Kubernetes, is disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containernodepool']


[ContainerNodePool.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego
