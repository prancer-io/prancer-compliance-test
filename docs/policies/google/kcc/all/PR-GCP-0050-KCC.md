



# Title: RSASHA1 For Signing


***<font color="white">Master Test Id:</font>*** TEST_DNSManagedZone_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([DNSManagedZone.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0050-KCC|
|eval|data.rule.rsasha1_for_signing|
|message|data.rule.rsasha1_for_signing_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** RSASHA1 is used for key signing in Cloud DNS zones.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['dnsmanagedzone']


[DNSManagedZone.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego
