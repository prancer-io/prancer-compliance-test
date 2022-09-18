



# Title: Ensure that the Redis Cache accepts only SSL connections


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-001|
|eval|data.rule.enableSslPort|
|message|data.rule.enableSslPort_err|
|remediationDescription|In Resource of type "Microsoft.Cache/redis" make sure properties.enableNonSslPort value is set to false or isn't exist .<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/linkedservers', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
