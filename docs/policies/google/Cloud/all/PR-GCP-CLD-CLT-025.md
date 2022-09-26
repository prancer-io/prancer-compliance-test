



# Title: GCP Kubernetes cluster not in redundant zones


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-025

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-025|
|eval|data.rule.k8s_zones|
|message|data.rule.k8s_zones_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_025.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Putting resources in different zones in a region provides isolation from many types of infrastructure, hardware, and software failures.<br><br> This policy alerts if your cluster is not located in at least 3 zones.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
