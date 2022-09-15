



# Master Test ID: PR-AZR-TRF-AKS-007


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-AKS-007|
|eval|data.rule.aks_api_server_authorized_ip_range_enabled|
|message|data.rule.aks_api_server_authorized_ip_range_enabled_err|
|remediationDescription|In 'azurerm_kubernetes_cluster' resource, make sure property 'api_server_authorized_ip_ranges' exist and its value has valid ip range to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_AKS_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** AKS shoud have an API Server Authorized IP Ranges enabled

***<font color="white">Description:</font>*** Authorized IP Ranges to kubernetes API server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_kubernetes_cluster']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego
