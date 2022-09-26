



# Title: Primitive Roles Used


***<font color="white">Master Test Id:</font>*** TEST_IAMPolicy_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([IAMpolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0052-KCC|
|eval|data.rule.primitive_roles_used|
|message|data.rule.primitive_roles_used_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['iampolicy']


[IAMpolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego
