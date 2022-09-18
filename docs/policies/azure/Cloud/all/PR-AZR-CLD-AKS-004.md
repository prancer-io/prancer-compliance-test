



# Title: Azure AKS cluster pool profile count should contain 3 nodes or more


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-004

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-004|
|eval|data.rule.aks_nodes|
|message|data.rule.aks_nodes_err|
|remediationDescription|In order to add additional worker nodes to your cluster pool, run the following CLI command: <br>az aks nodepool add --cluster-name --name --resource-group|
|remediationFunction|PR_AZR_CLD_AKS_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure your AKS cluster pool profile count contains 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
