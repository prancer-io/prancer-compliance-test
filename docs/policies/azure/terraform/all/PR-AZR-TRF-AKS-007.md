



# Master Test ID: PR-AZR-TRF-AKS-007


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(aks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-AKS-007|
|eval: |data.rule.aks_api_server_authorized_ip_range_enabled|
|message: |data.rule.aks_api_server_authorized_ip_range_enabled_err|
|remediationDescription: |In 'azurerm_kubernetes_cluster' resource, make sure property 'api_server_authorized_ip_ranges' exist and its value has valid ip range to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_AKS_007.py|


severity: Low

title: AKS shoud have an API Server Authorized IP Ranges enabled

description: Authorized IP Ranges to kubernetes API server  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |[]|
|service: |['terraform']|


resourceTypes: ['azurerm_kubernetes_cluster']


[file(aks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
