



# Title: Ensure Kubernetes Engine Clusters using the default network in Google Cloud Provider


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CLT-019

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CLT-019|
|eval|data.rule.k8s_network|
|message|data.rule.k8s_network_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CLT_019.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Google Kubernetes Engine (GKE) clusters that are configured to use the default network. Because GKE uses this network when creating routes and firewalls for the cluster, as a best practice define a network configuration that meets your security and networking requirements for ingress and egress traffic, instead of using the default network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['container.v1.cluster']


[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/container.rego
