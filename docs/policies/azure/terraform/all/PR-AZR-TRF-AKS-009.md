



# Title: Kubernetes Dashboard shoud be disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-AKS-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-009|
|eval|data.rule.aks_kub_dashboard_disabled|
|message|data.rule.aks_kub_dashboard_disabled_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, set 'kube_dashboard.enabled = true' under 'addon_profile' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#kube_dashboard' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disable the Kubernetes dashboard on Azure Kubernetes Service  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
