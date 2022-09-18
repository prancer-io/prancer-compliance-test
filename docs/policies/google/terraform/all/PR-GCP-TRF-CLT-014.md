



# Title: GCP Kubernetes Engine Clusters have pod security policy disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-014

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-014|
|eval|data.rule.k8s_pod_security|
|message|data.rule.k8s_pod_security_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Clusters which have pod security policy disabled. The Pod Security Policy defines a set of conditions that pods must meet to be accepted by the cluster; when a request to create or update a pod does not meet the conditions in the pod security policy, that request is rejected and an error is returned.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
