



# Title: Azure storage account queue services diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-006|
|eval|data.rule.log_queue|
|message|data.rule.log_queue_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. Should be enabled for queues|
|remediationFunction|PR_AZR_ARM_MNT_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Queue logging cannot be enabled for Storage Accounts with 'kind' of BlobStorage **<br><br>Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:<br>- Timing and server latency.<br>- Success or failure, and HTTP status code.<br>- Authentication details<br><br>This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings', 'microsoft.network/loadbalancers/providers/diagnosticsettings', 'microsoft.keyvault/vaults/providers/diagnosticsettings']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
