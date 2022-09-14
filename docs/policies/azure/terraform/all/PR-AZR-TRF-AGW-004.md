



# Master Test ID: PR-AZR-TRF-AGW-004


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(applicationgateways.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AGW-004|
|eval: |data.rule.frontendPublicIPConfigurationsDisabled|
|message: |data.rule.frontendPublicIPConfigurationsDisabled_err|
|remediationDescription: |For resource type 'azurerm_application_gateway' make sure 'public_ip_address_id' does not exist under 'frontend_ip_configuration' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#frontend_ip_configuration' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AGW_004.py|


severity: High

title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured

description: Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_application_gateway']


[file(applicationgateways.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego
