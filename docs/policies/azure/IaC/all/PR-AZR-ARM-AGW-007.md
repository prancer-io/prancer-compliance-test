



# Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AGW-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AGW-007|
|eval|data.rule.application_gateways_v2_waf_ruleset_OWASP_active|
|message|data.rule.application_gateways_v2_waf_ruleset_OWASP_active_err|
|remediationDescription|For resource type 'microsoft.network/applicationgateways' make sure 'properties.sku.name' and 'properties.sku.tier' contains either 'Standard_v2' or 'WAF_v2', value of 'properties.webApplicationFirewallConfiguration.enabled' is set to true, value of 'properties.webApplicationFirewallConfiguration.ruleSetType' is set to 'OWASP' and 'properties.webApplicationFirewallConfiguration.ruleSetVersion' has minimum '3.1' to fix the issue.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways?tabs=json#applicationgatewaywebapplicationfirewallconfiguration' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AGW_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.network/applicationgateways']


[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego
