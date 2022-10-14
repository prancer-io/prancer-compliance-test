



# Title: Azure storage account blob services diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-005

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-005|
|eval|data.rule.log_blob|
|message|data.rule.log_blob_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. Should be enabled for blobs|
|remediationFunction|PR_AZR_ARM_MNT_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Storage Logging records details of requests (read, write, and delete operations) against your Azure blobs. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for blobs. As a best practice, enable logging for read, write, and delete request types on blobs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings', 'microsoft.network/loadbalancers/providers/diagnosticsettings', 'microsoft.keyvault/vaults/providers/diagnosticsettings']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
