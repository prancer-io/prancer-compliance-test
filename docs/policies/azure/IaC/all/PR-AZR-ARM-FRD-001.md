



# Title: Azure frontDoors should have configured with WAF policy with Default Rule Set 1.0/1.1 for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-FRD-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([frontdoors.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-FRD-001|
|eval|data.rule.frontdoors_has_drs_configured|
|message|data.rule.frontdoors_has_drs_configured_err|
|remediationDescription|For resource type 'microsoft.network/frontdoors' make sure 'properties.webApplicationFirewallPolicyLink.id' contains 'id' from 'microsoft.network/frontdoorwebapplicationfirewallpolicies' under 'properties.frontendEndpoints' array. Also make sure 'microsoft.network/frontdoorwebapplicationfirewallpolicies' 'properties.managedRules.managedRuleSets' contains either 'Microsoft_DefaultRuleSet' or 'DefaultRuleSet' as ruleSetType and '1.1' or '1.0' as ruleSetVersion respectively to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/frontdoors?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_FRD_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended to enable WAF policy with Default Rule Set 1.0/1.1 on Front Door deployments to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/frontdoors', 'microsoft.network/frontdoorwebapplicationfirewallpolicies']


[frontdoors.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/frontdoors.rego
