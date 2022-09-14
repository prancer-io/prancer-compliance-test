



# Master Test ID: PR-AZR-TRF-AGW-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(applicationgateways.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AGW-007|
|eval: |data.rule.application_gateways_v2_waf_ruleset_OWASP_active|
|message: |data.rule.application_gateways_v2_waf_ruleset_OWASP_active_err|
|remediationDescription: |For resource type 'azurerm_application_gateway' make sure 'properties.sku.name' and 'properties.sku.tier' contains either 'Standard_v2' or 'WAF_v2', value of 'properties.waf_configuration.enabled' is set to true, value of 'properties.waf_configuration.rule_set_type' is set to 'OWASP' and 'properties.webApplicationFirewallConfiguration.rule_set_version' has minimum '3.1' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#waf_configuration' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AGW_007.py|


severity: High

title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit

description: It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_application_gateway']


[file(applicationgateways.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego
