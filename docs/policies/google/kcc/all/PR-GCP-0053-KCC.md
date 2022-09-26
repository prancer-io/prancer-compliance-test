



# Title: Redis Role Used On Org


***<font color="white">Master Test Id:</font>*** TEST_IAMPolicy_3

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([IAMpolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0053-KCC|
|eval|data.rule.redis_role_used_on_org|
|message|data.rule.redis_role_used_on_org_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A Redis IAM role is assigned at the organization or folder level.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['iampolicy']


[IAMpolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego
