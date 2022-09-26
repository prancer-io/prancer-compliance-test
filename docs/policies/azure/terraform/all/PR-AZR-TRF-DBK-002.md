



# Title: Azure Databricks should have vnet integration


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-DBK-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([databricks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-DBK-002|
|eval|data.rule.databrics_workspace_has_vnet_integration|
|message|data.rule.databrics_workspace_has_vnet_integration_err|
|remediationDescription|In 'azurerm_databricks_workspace' resource, set set vnet id as the value of 'virtual_network_id' under 'custom_parameters' block to fix the issue. If 'custom_parameters' block does not exist please add one. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_DBK_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have vnet integration and warn.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_databricks_workspace']


[databricks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/databricks.rego
