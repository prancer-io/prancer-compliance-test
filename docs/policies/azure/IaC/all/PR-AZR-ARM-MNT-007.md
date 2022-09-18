



# Title: Azure storage account table services diagnostic logs should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-MNT-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([diagnosticsettings.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-MNT-007|
|eval|data.rule.log_table|
|message|data.rule.log_table_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/diagnosticsettings' target='_blank'>here</a>. Should be enabled for tables|
|remediationFunction|PR_AZR_ARM_MNT_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:_x005F<br>- Timing and server latency._x005F<br>- Success or failure, and HTTP status code._x005F<br>- Authentication details_x005F<br>_x005F<br>This policy identifies Azure storage accounts that do not have logging enabled for tables. As a best practice, enable logging for read, write, and delete request types on tables.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/queueservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/tableservices/providers/diagnosticsettings', 'microsoft.storage/storageaccounts/blobservices/providers/diagnosticsettings', 'microsoft.network/loadbalancers/providers/diagnosticsettings', 'microsoft.keyvault/vaults/providers/diagnosticsettings']


[diagnosticsettings.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/diagnosticsettings.rego
