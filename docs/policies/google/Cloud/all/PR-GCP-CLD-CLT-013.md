



# Title: Ensure GCP Kubernetes Engine Clusters not have legacy compute engine metadata endpoints disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-013

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-013|
|eval|data.rule.k8s_legacy_endpoint|
|message|data.rule.k8s_legacy_endpoint_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
