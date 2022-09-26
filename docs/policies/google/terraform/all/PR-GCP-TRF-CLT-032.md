



# Title: Ensure GCP Kubernetes cluster shielded GKE node with Secure Boot enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-032

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-032|
|eval|data.rule.k8s_secure_boot|
|message|data.rule.k8s_secure_boot_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a> |
|remediationFunction|PR_GCP_TRF_CLT_032.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Kubernetes cluster shielded GKE nodes with Secure Boot disabled. An attacker may seek to alter boot components to persist malware or rootkits during system initialization. It is recommended to enable Secure Boot for Shielded GKE Nodes to verify the digital signature of node boot components.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
