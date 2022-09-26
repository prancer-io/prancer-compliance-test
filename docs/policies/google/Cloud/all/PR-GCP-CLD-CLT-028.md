



# Title: Ensure GCP Kubernetes Engine cluster workload identity is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-028

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-028|
|eval|data.rule.k8s_workload|
|message|data.rule.k8s_workload_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a> |
|remediationFunction|PR_GCP_CLD_CLT_028.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Kubernetes Engine clusters for which workload identity is disabled. Manual approaches for authenticating Kubernetes workloads violates the principle of least privilege on a multi-tenanted node when one pod needs to have access to a service, but every other pod on the node that uses the service account does not. Enabling Workload Identity manages the distribution and rotation of Service account keys for the workloads to use.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
