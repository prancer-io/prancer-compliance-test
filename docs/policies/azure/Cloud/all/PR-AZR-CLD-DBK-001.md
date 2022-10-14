



# Title: Azure Databricks should not use public IP address


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-DBK-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_440']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([databricks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-DBK-001|
|eval|data.rule.databrics_workspace_has_public_ip_disabled|
|message|data.rule.databrics_workspace_has_public_ip_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/vnet-inject' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_DBK_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have public ip disabled and warn.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Analytics']|



[databricks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/databricks.rego
