



# Title: SSL Not Enforced


***<font color="white">Master Test Id:</font>*** TEST_SQLInstance_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([SQLInstance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0057-KCC|
|eval|data.rule.ssl_not_enforced|
|message|data.rule.ssl_not_enforced_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A Cloud SQL database instance doesn't require all incoming connections to use SSL.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['sqlinstance']


[SQLInstance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego
