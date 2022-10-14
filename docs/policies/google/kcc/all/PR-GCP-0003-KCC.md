



# Title: Firewall Rule Logging Disabled


***<font color="white">Master Test Id:</font>*** TEST_ComputeFirewall_2

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ComputeFirewall.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0003-KCC|
|eval|data.rule.firewall_rule_logging_disabled|
|message|data.rule.firewall_rule_logging_disabled_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Firewall rule logging is disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['computefirewall']


[ComputeFirewall.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego
