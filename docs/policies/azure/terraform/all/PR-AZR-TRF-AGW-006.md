



# Master Test ID: PR-AZR-TRF-AGW-006


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(applicationgateways.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AGW-006|
|eval: |data.rule.secret_certificate_is_in_keyvalut|
|message: |data.rule.secret_certificate_is_in_keyvalut_err|
|remediationDescription: |For resource type 'azurerm_application_gateway' make sure 'key_vault_secret_id' has target key vault id under 'ssl_certificate' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#key_vault_secret_id' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AGW_006.py|


severity: High

title: Ensure Application Gateway secret certificates stores in keyvault

description: This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service: |['terraform']|


resourceTypes: ['azurerm_application_gateway']


[file(applicationgateways.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego
