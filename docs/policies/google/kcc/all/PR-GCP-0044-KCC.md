



# Title: Workload Identity Disabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerCluster_10

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerCluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0044-KCC|
|eval|data.rule.workload_identity_disabled|
|message|data.rule.workload_identity_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Workload Identity is disabled on a GKE cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containercluster']


[ContainerCluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego
