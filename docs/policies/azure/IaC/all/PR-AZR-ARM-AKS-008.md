



# Title: Ensure AKS cluster network policies are enforced


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-AKS-008

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-AKS-008|
|eval|data.rule.network_policy|
|message|data.rule.network_policy_err|
|remediationDescription|For Resource type 'microsoft.containerservice/managedclusters' make sure networkProfile.networkPolicy exists and the value is set to `azure` or 'calico`.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_AKS_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Network policy options in AKS include two ways to implement a network policy. You can choose between Azure Network Policies or Calico Network Policies. In both cases, the underlying controlling layer is based on Linux IPTables to enforce the specified policies. Policies are translated into sets of allowed and disallowed IP pairs. These pairs are then programmed as IPTable rules.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.containerservice/managedclusters']


[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/aks.rego
