



# Title: Private Cluster Disabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerCluster_8

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerCluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0042-KCC|
|eval|data.rule.private_cluster_disabled|
|message|data.rule.private_cluster_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A GKE cluster has a Private cluster disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containercluster']


[ContainerCluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego
