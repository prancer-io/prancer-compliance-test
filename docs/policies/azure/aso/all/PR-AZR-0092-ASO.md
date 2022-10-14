



# Title: Storage Accounts without Secure transfer enabled


***<font color="white">Master Test Id:</font>*** TEST_Storage_Accounts

***<font color="white">Master Snapshot Id:</font>*** ['ASO_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-0092-ASO|
|eval|data.rule.storage_secure|
|message|data.rule.storage_secure_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage does not support HTTPs for custom domain names, this option is not applied when using a custom domain name.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['aso']|


***<font color="white">Resource Types:</font>*** ['storageaccount']


[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/aso/storageaccounts.rego
