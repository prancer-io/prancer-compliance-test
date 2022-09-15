



# Master Test ID: PR-AZR-TRF-AKS-008


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-008|
|eval|data.rule.aks_network_policy_configured|
|message|data.rule.aks_network_policy_configured_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set network_policy = 'azure' under 'network_profile' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** AKS cluster should have Network Policy configured

***<font color="white">Description:</font>*** Network policy used for building Kubernetes network. - calico or azure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
