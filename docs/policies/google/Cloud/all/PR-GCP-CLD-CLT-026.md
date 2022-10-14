



# Title: GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-026

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-026|
|eval|data.rule.k8s_auto_upgrade|
|message|data.rule.k8s_auto_upgrade_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a> |
|remediationFunction|PR_GCP_CLD_CLT_026.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure your Kubernetes cluster size contains 3 or more nodes. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br> This policy checks the size of your cluster pools and alerts if there are fewer than 3 nodes in a pool.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
