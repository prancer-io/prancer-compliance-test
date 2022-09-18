



# Title: Azure Databricks should not use public IP address


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-DBK-001

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([databricks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-DBK-001|
|eval|data.rule.databrics_workspace_has_public_ip_disabled|
|message|data.rule.databrics_workspace_has_public_ip_disabled_err|
|remediationDescription|In Resource of type "microsoft.databricks/workspaces" make sure properties.parameters.enableNoPublicIp exist and its value set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_DBK_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have public ip disabled and warn.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.databricks/workspaces']


[databricks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/databricks.rego
