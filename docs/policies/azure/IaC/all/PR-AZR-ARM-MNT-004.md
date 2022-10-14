



# Title: Azure Storage Account diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-004

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-004|
|eval|data.rule.log_storage_retention|
|message|data.rule.log_storage_retention_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. Make sure to enable diagnostics settings for load balancers|
|remediationFunction|PR_AZR_ARM_MNT_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Storage Account provide different types of logs alert events, health probe, metrics to help you manage and troubleshoot issues. This policy identifies Azure Storage Account that have diagnostics logs disabled. As a best practice, enable diagnostic logs to start collecting the data available through these logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings', 'microsoft.network/loadbalancers/providers/diagnosticsettings', 'microsoft.keyvault/vaults/providers/diagnosticsettings']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
