



# Title: Managed Azure AD RBAC for AKS cluster should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-AKS-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-006|
|eval|data.rule.aks_aad_rbac_enabled|
|message|data.rule.aks_aad_rbac_enabled_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set role_based_access_control.azure_active_directory.managed = true to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#role_based_access_control' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
