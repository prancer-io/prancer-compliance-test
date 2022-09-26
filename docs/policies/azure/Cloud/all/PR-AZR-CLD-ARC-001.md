



# Title: Ensure that the Redis Cache accepts only SSL connections


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ARC-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_420']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ARC-001|
|eval|data.rule.enableSslPort|
|message|data.rule.enableSslPort_err|
|remediationDescription|In Azure Portal:<br>1. Go to Redis Caches.<br>2. For each Redis Cache:<br>3. Click on Advanced settings<br>4. Set the Allow access only via SSL to 'Yes'<br>5. Select Save<br><br>Default Value:<br>By default, non-SSL access is disabled for new caches.<br><br>References:<br><a href='https://docs.microsoft.com/en-us/azure/redis-cache/cache-configure#advanced-settings' target='_blank'>https://docs.microsoft.com/en-us/azure/redis-cache/cache-configure#advanced-settings</a>|
|remediationFunction|PR_AZR_CLD_ARC_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['Databases']|



[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Redis.rego
