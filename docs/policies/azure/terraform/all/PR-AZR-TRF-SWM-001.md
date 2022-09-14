



# Master Test ID: PR-AZR-TRF-SWM-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(synapse_workspace.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SWM-001|
|eval: |data.rule.synapse_workspace_enables_managed_virtual_network|
|message: |data.rule.synapse_workspace_enables_managed_virtual_network_err|
|remediationDescription: |In 'azurerm_synapse_workspace' resource, set 'managed_virtual_network_enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace#managed_virtual_network_enabled' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SWM_001.py|


severity: High

title: Managed workspace virtual network on Azure Synapse workspaces should be enabled

description: Enabling a managed workspace virtual network ensures that your workspace is network isolated from other workspaces. Data integration and Spark resources deployed in this virtual network also provides user level isolation for Spark activities.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_synapse_workspace']


[file(synapse_workspace.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/synapse_workspace.rego
