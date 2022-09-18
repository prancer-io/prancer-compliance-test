



# Title: Legacy Authorization Enabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerCluster_4

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerCluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0038-KCC|
|eval|data.rule.legacy_authorization_enabled|
|message|data.rule.legacy_authorization_enabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Legacy Authorization is enabled on GKE clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containercluster']


[ContainerCluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego
