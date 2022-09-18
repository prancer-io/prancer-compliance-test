



# Title: GCP Kubernetes Engine Clusters using the default network


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-019

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-019|
|eval|data.rule.k8s_network|
|message|data.rule.k8s_network_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
