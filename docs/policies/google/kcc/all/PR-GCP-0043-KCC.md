



# Title: Web UI Enabled


***<font color="white">Master Test Id:</font>*** TEST_ContainerCluster_9

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ContainerCluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0043-KCC|
|eval|data.rule.web_ui_enabled|
|message|data.rule.web_ui_enabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The GKE web UI (dashboard) is enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['containercluster']


[ContainerCluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego
