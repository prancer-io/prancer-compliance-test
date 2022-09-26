



# Title: Azure Kubernetes Service Clusters should have local authentication methods disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-010

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-010|
|eval|data.rule.aks_local_account_disabled|
|message|data.rule.aks_local_account_disabled_err|
|remediationDescription|For resource type 'microsoft.containerservice/managedclusters' make sure property 'disableLocalAccounts' exist and its value set to 'true' to fix the issue. Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters?tabs=json' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_AKS_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disabling local authentication methods improves security by ensuring that Azure Kubernetes Service Clusters should exclusively require Azure Active Directory identities for authentication.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
