



# Title: Ensure Application Gateway Backend is using Https protocol


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AGW-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AGW-005|
|eval|data.rule.backend_https_protocol_enabled|
|message|data.rule.backend_https_protocol_enabled_err|
|remediationDescription|For resource type 'microsoft.network/applicationgateways' make sure 'properties.protocol' has value 'https' under 'backendHttpSettingsCollection' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways?tabs=json#applicationgatewaybackendhttpsettings' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AGW_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/applicationgateways']


[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego
