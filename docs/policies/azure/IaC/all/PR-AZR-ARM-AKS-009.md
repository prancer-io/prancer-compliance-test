



# Title: Ensure Kubernetes Dashboard is disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-009

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-009|
|eval|data.rule.aks_kub_dashboard_disabled|
|message|data.rule.aks_kub_dashboard_disabled_err|
|remediationDescription|For resource type 'microsoft.containerservice/managedclusters' make sure property 'addonProfiles.kubeDashboard.enabled' exist and its value set to 'false' to fix the issue. Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AKS_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disable the Kubernetes dashboard on Azure Kubernetes Service  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
