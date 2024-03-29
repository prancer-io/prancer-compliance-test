



# Title: Azure frontDoors should have configured with WAF policy with Default Rule Set 1.0/1.1 for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-FRD-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([frontdoors.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-FRD-001|
|eval|data.rule.frontdoors_has_drs_configured|
|message|data.rule.frontdoors_has_drs_configured_err|
|remediationDescription|In 'azurerm_frontdoor' resource, make sure 'web_application_firewall_policy_link_id' contains 'id' from 'azurerm_frontdoor_firewall_policy' under 'frontend_endpoint' block. Also make sure 'azurerm_frontdoor_firewall_policy' 'properties.managed_rule' contains either 'Microsoft_DefaultRuleSet' or 'DefaultRuleSet' as type and '1.1' or '1.0' as version respectively to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/frontdoor#web_application_firewall_policy_link_id' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_FRD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended to enable WAF policy with Default Rule Set 1.0/1.1 on Front Door deployments to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_frontdoor', 'azurerm_frontdoor_firewall_policy']


[frontdoors.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/frontdoors.rego
