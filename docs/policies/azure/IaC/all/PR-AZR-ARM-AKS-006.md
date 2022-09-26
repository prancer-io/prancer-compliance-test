



# Title: Managed Azure AD RBAC for AKS cluster should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-006

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-006|
|eval|data.rule.aks_aad_azure_rbac|
|message|data.rule.aks_aad_azure_rbac_err|
|remediationDescription|Make sure aadProfile property of type object exist in ARM template with boolean managed = true and enableAzureRBAC = true as child property. Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters?tabs=json#managedclusteraadprofile-object' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AKS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. Visit https://docs.microsoft.com/en-us/azure/aks/azure-ad-rbac for details.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
