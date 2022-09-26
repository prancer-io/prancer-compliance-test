



# Title: Ensure AKS API server defines authorized IP ranges


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-007|
|eval|data.rule.aks_authorized_Ip|
|message|data.rule.aks_authorized_Ip_err|
|remediationDescription|API server authorized IP ranges only work for new AKS clusters and are not supported for private AKS clusters.<br><br>To create a cluster with API server authorized IP ranges enabled : <a href='https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges?ocid=AID754288&wt.mc_id=CFID0533#create-an-aks-cluster-with-api-server-authorized-ip-ranges-enabled' target='_blank'>https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges?ocid=AID754288&wt.mc_id=CFID0533#create-an-aks-cluster-with-api-server-authorized-ip-ranges-enabled</a><br><br>To update a cluster's API server authorized IP ranges: <a href='https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges?ocid=AID754288&wt.mc_id=CFID0533#update-a-clusters-api-server-authorized-ip-ranges' target='_blank'>https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges?ocid=AID754288&wt.mc_id=CFID0533#update-a-clusters-api-server-authorized-ip-ranges</a>|
|remediationFunction|PR_AZR_CLD_AKS_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** The AKS API server receives requests to perform actions in the cluster , for example, to create resources, and scale the number of nodes. The API server provides a secure way to manage a cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
