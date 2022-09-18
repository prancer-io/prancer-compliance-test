



# Title: Bucket CMEK Disabled


***<font color="white">Master Test Id:</font>*** TEST_ComputeSubnetwork

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeSubnetwork.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0034-KCC|
|eval|data.rule.private_google_access_disabled|
|message|data.rule.private_google_access_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** There are private subnetworks without access to Google public APIs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computesubnetwork']


[ComputeSubnetwork.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeSubnetwork.rego
