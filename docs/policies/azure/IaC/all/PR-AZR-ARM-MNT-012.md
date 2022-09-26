



# Title: Redis Cache audit logging should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-012

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-012|
|eval|data.rule.log_redis_cache|
|message|data.rule.log_redis_cache_err|
|remediationDescription|Make sure you are following the diagnostic settings ARM template guidelines by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. This settings should be enabled for redis cache|
|remediationFunction|PR_AZR_ARM_MNT_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Diagnostic settings for redis cache used to stream resource logs to a Log Analytics workspace. this policy will identify any redis cache which has this diagnostic settings missing or misconfigured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.insights/diagnosticsettings', 'microsoft.cache/redis']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
