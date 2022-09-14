



# Master Test ID: PR-AZR-TRF-ACR-002


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(registry.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ACR-002|
|eval: |data.rule.adminUserDisabled|
|message: |data.rule.adminUserDisabled_err|
|remediationDescription: |In 'azurerm_container_registry' resource, set 'admin_enabled = false' or remove 'admin_enabled' property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry#admin_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ACR_002.py|


severity: High

title: Ensure that admin user is disabled for Container Registry

description: The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_container_registry']


[file(registry.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/registry.rego
