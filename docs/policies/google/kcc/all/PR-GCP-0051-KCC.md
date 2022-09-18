



# Title: Audit Logging Disabled


***<font color="white">Master Test Id:</font>*** TEST_IAMpolicy_1

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([IAMpolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0051-KCC|
|eval|data.rule.audit_logging_disabled|
|message|data.rule.audit_logging_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Audit logging has been disabled for this resource.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['iampolicy']


[IAMpolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego
