



# Title: Ensure Kubernetes Dashboard is disabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AKS-009

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_219']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([aks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AKS-009|
|eval|data.rule.aks_kub_dashboard_disabled|
|message|data.rule.aks_kub_dashboard_disabled_err|
|remediationDescription|Use CLI Command: <br><br>az aks disable-addons -g myRG -n myAKScluster -a kube-dashboard|
|remediationFunction|PR_AZR_CLD_AKS_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Disable the Kubernetes dashboard on Azure Kubernetes Service  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Containers']|



[aks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/aks.rego
