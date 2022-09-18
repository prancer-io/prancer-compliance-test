



# Title: Azure Kubernetes Service Clusters should have local authentication methods disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-010

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-010|
|eval|data.rule.aks_local_account_disabled|
|message|data.rule.aks_local_account_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/aks/private-clusters' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AKS_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disabling local authentication methods improves security by ensuring that Azure Kubernetes Service Clusters should exclusively require Azure Active Directory identities for authentication.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
