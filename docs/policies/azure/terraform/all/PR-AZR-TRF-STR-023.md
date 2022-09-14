



# Master Test ID: PR-AZR-TRF-STR-023


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(storageaccounts.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-STR-023|
|eval: |data.rule.storage_acl_usage_vnet|
|message: |data.rule.storage_acl_usage_vnet_err|
|remediationDescription: |In 'azurerm_storage_account_network_rules' resource or 'azurerm_storage_account's inner block 'network_rules', set 'default_action = Deny' and set id of target 'azurerm_subnet' into property 'virtual_network_subnet_ids' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#virtual_network_subnet_ids' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_STR_023.py|


severity: High

title: Storage Accounts should use a virtual network service endpoint

description: This policy audits any Storage Account not configured to use a virtual network service endpoint.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_storage_account', 'azurerm_storage_account_network_rules']


[file(storageaccounts.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego
