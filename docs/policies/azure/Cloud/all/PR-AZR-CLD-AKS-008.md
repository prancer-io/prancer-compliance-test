



# Title: Ensure AKS cluster network policies are enforced


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-008

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-008|
|eval|data.rule.network_policy|
|message|data.rule.network_policy_err|
|remediationDescription|In an AKS cluster, all pods can send and receive traffic without limitations, by default. To improve security, you can define rules that control the flow of traffic.<br>Network Policy is a Kubernetes specification that defines access policies for communication between Pods. These network policy rules are defined as YAML manifests.<br>The network policy feature can only be enabled when the cluster is created. You can't enable network policy on an existing AKS cluster.<br>To create AKS cluster that supports network policy, please refer - <br><a href='https://docs.microsoft.com/en-us/azure/aks/use-network-policies?ocid=AID754288&wt.mc_id=CFID0471#create-an-aks-cluster-and-enable-network-policy' target='_blank'>https://docs.microsoft.com/en-us/azure/aks/use-network-policies?ocid=AID754288&wt.mc_id=CFID0471#create-an-aks-cluster-and-enable-network-policy</a>|
|remediationFunction|PR_AZR_CLD_AKS_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Network policy options in AKS include two ways to implement a network policy. You can choose between Azure Network Policies or Calico Network Policies. In both cases, the underlying controlling layer is based on Linux IPTables to enforce the specified policies. Policies are translated into sets of allowed and disallowed IP pairs. These pairs are then programmed as IPTable rules.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
