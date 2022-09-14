



# Master Test ID: PR-AZR-TRF-AGW-005


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(applicationgateways.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AGW-005|
|eval: |data.rule.backend_https_protocol_enabled|
|message: |data.rule.backend_https_protocol_enabled_err|
|remediationDescription: |For resource type 'azurerm_application_gateway' make sure 'protocol' has value 'https' under 'backend_http_settings' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#backend_http_settings' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AGW_005.py|


severity: High

title: Ensure Application Gateway Backend is using Https protocol

description: Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_application_gateway']


[file(applicationgateways.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego
