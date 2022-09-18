



# Title: Legacy Metadata Enabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerNodePool_4

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerNodePool.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0048-KCC|
|eval|data.rule.legacy_metadata_enabled|
|message|data.rule.legacy_metadata_enabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Legacy metadata is enabled on GKE clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containernodepool']


[ContainerNodePool.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego
