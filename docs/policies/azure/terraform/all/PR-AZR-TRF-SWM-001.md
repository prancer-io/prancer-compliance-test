



# Master Test ID: PR-AZR-TRF-SWM-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([synapse_workspace.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SWM-001|
|eval|data.rule.synapse_workspace_enables_managed_virtual_network|
|message|data.rule.synapse_workspace_enables_managed_virtual_network_err|
|remediationDescription|In 'azurerm_synapse_workspace' resource, set 'managed_virtual_network_enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace#managed_virtual_network_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SWM_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Managed workspace virtual network on Azure Synapse workspaces should be enabled

***<font color="white">Description:</font>*** Enabling a managed workspace virtual network ensures that your workspace is network isolated from other workspaces. Data integration and Spark resources deployed in this virtual network also provides user level isolation for Spark activities.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_synapse_workspace']


[synapse_workspace.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/synapse_workspace.rego
