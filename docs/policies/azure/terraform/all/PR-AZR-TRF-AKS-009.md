



# Master Test ID: PR-AZR-TRF-AKS-009


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(aks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AKS-009|
|eval: |data.rule.aks_kub_dashboard_disabled|
|message: |data.rule.aks_kub_dashboard_disabled_err|
|remediationDescription: |In 'azurerm_kubernetes_cluster' resource, set 'kube_dashboard.enabled = true' under 'addon_profile' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#kube_dashboard' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AKS_009.py|


severity: Medium

title: Kubernetes Dashboard shoud be disabled

description: Disable the Kubernetes dashboard on Azure Kubernetes Service  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_kubernetes_cluster']


[file(aks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
