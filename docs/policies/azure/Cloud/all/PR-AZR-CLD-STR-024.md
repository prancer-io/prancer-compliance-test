



# Title: Storage accounts should prevent shared key access


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-STR-024

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_301']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storageaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-STR-024|
|eval|data.rule.storage_account_allow_shared_key_access|
|message|data.rule.storage_account_allow_shared_key_access_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent?tabs=portal' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_STR_024.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key and is recommended by Microsoft.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|Azure|
|compliance|['Best Practice']|
|service|['Storage']|



[storageaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/storageaccounts.rego
