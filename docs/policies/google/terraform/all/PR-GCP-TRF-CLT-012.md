



# Title: Ensure GCP Kubernetes Engine Clusters not have binary authorization enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-012|
|eval|data.rule.k8s_binary_auth|
|message|data.rule.k8s_binary_auth_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
