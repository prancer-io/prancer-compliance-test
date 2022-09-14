



# Master Test ID: PR-AZR-TRF-ASC-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(pricing.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ASC-001|
|eval: |data.rule.pricing|
|message: |data.rule.pricing_err|
|remediationDescription: |In 'azurerm_security_center_subscription_pricing' resource, set tier = 'standard' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ASC_001.py|


severity: Medium

title: Azure Security Center should have pricing tier configured to 'standard'

description: Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CIS', 'ISO 27001']|
|service: |['terraform']|


resourceTypes: ['azurerm_security_center_subscription_pricing']


[file(pricing.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/pricing.rego
