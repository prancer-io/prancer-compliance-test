



# Title: Ensure GCP Kubernetes cluster Shielded GKE Nodes feature enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-029

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-029|
|eval|data.rule.k8s_shield_node|
|message|data.rule.k8s_shield_node_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a> |
|remediationFunction|PR_GCP_CLD_CLT_029.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Kubernetes clusters for which the Shielded GKE Nodes feature is not enabled. Shielded GKE nodes protect clusters against boot- or kernel-level malware or rootkits
which persist beyond infected OS. It is recommended to enable Shielded GKE Nodes for all the Kubernetes clusters.

FMI: https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
