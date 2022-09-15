



# Master Test ID: PR-AZR-TRF-AFW-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([azure_firewalls.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AFW-001|
|eval|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection|
|message|data.rule.azure_firewall_configured_with_idpc_and_tls_inspection_err|
|remediationDescription|In 'azurerm_firewall' resource, make sure property 'sku_tier' contains 'Premium', value of 'properties.firewall_policy_id' contains 'id' of 'azurerm_firewall_policy'. Also make sure 'azurerm_firewall_policy' 'properties.sku' contains 'Premium', value of 'properties.intrusion_detection.mode' is set to 'Deny' and 'properties.tls_certificate.key_vault_secret_id' has 'id' of target 'azurerm_key_vault_secret' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall#firewall_policy_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AFW_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Firewall Premium should be configured with both IDPS Alert & Deny mode and TLS inspection enabled for proactive protection against CVE-2021-44228 exploit

***<font color="white">Description:</font>*** Azure Firewall Premium has enhanced protection from the Log4j RCE CVE-2021-44228 vulnerability and exploit. Azure Firewall premium IDPS (Intrusion Detection and Prevention System) provides IDPS inspection for all east-west traffic and outbound traffic to internet. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_firewall', 'azurerm_firewall_policy', 'azurerm_key_vault_secret']


[azure_firewalls.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/azure_firewalls.rego
