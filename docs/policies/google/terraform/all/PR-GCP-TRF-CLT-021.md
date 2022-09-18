



# Title: GCP Kubernetes Engine Clusters without any label information


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-021

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-021|
|eval|data.rule.k8s_labels|
|message|data.rule.k8s_labels_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
