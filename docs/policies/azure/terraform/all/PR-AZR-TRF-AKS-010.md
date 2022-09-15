



# Master Test ID: PR-AZR-TRF-AKS-010


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-010|
|eval|data.rule.aks_local_account_disabled|
|message|data.rule.aks_local_account_disabled_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set 'local_account_disabled = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#local_account_disabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Azure Kubernetes Service Clusters should have local authentication methods disabled

***<font color="white">Description:</font>*** Disabling local authentication methods improves security by ensuring that Azure Kubernetes Service Clusters should exclusively require Azure Active Directory identities for authentication.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
