



# Title: Storage Accounts location configuration should be inside of Europe


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-009

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-009|
|eval|data.rule.region|
|message|data.rule.region_err|
|remediationDescription|Please refer to Azure documentations about Storage Accounts:<br><a href='https://docs.microsoft.com/en-us/azure/storage/common/storage-create-storage-account' target='_blank'>here</a>.<br>and<br>Azure documentations about Regions:<br><a href='https://azure.microsoft.com/en-us/global-infrastructure/regions/#services' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Identify Storage Accounts outside of the following regions: northeurope, westeurope  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['GDPR']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
