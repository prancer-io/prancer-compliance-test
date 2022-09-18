



# Title: Managed Azure AD RBAC for AKS cluster should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-006

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-006|
|eval|data.rule.aks_aad_azure_rbac|
|message|data.rule.aks_aad_azure_rbac_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/aks/managed-aad' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_AKS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. Visit https://docs.microsoft.com/en-us/azure/aks/azure-ad-rbac for details.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
