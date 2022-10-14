



# Title: Azure Firewall Premium should be configured with both IDPS Alert & Deny mode and TLS inspection enabled for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AFW-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([azure_firewalls.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AFW-001|
|eval|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection|
|message|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection_err|
|remediationDescription|For resource type 'microsoft.network/azurefirewalls' make sure 'properties.sku.tier' contains 'Premium', value of 'properties.firewallPolicy.id' contains 'id' of 'microsoft.network/firewallpolicies'. Also make sure 'microsoft.network/firewallpolicies' 'properties.sku.tier' contains 'Premium', value of 'properties.intrusionDetection.mode' is set to 'Deny' and 'properties.transportSecurity.certificateAuthority.keyVaultSecretId' has 'id' of target 'microsoft.keyvault/vaults/secrets' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/azurefirewalls?tabs=json#firewallPolicy' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AFW_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Firewall Premium has enhanced protection from the Log4j RCE CVE-2021-44228 vulnerability and exploit. Azure Firewall premium IDPS (Intrusion Detection and Prevention System) provides IDPS inspection for all east-west traffic and outbound traffic to internet. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/azurefirewalls', 'microsoft.network/firewallpolicies']


[azure_firewalls.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/azure_firewalls.rego
