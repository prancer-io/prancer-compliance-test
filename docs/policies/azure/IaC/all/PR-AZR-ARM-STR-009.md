



# Title: Storage Accounts location configuration should be inside of Europe


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-STR-009

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-STR-009|
|eval|data.rule.region|
|message|data.rule.region_err|
|remediationDescription|In Resource of type "Microsoft.storage/storageaccounts" make sure location is set to northeurope or westeurope.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_STR_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Identify Storage Accounts outside of the following regions: northeurope, westeurope  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.storage/storageaccounts']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/storageaccounts.rego
