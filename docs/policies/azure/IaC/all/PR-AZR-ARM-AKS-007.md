



# Title: Ensure AKS API server defines authorized IP ranges


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-007

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-007|
|eval|data.rule.aks_authorized_Ip|
|message|data.rule.aks_authorized_Ip_err|
|remediationDescription|For Resource type 'microsoft.containerservice/managedclusters' make sure apiServerAccessProfile.authorizedIPRanges exists and the value of that be accessible from a limited set of IP address ranges.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_AKS_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** The AKS API server receives requests to perform actions in the cluster , for example, to create resources, and scale the number of nodes. The API server provides a secure way to manage a cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
