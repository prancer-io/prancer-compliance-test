



# Title: Redis Cache Firewall rules should not configure to allow full inbound access to everyone


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-ARC-008

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-ARC-008|
|eval|data.rule.redis_cache_firewall_not_allowing_full_inbound_access|
|message|data.rule.redis_cache_firewall_not_allowing_full_inbound_access_err|
|remediationDescription|In 'Microsoft.Cache/redis' resource, set valid ip range other then '0.0.0.0' between 'start_ip' and 'end_ip' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.cache/redis' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_ARC_008.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Firewalls grant access to redis cache based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.cache/redis/firewallrules', 'microsoft.cache/redis']


[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/Redis.rego
