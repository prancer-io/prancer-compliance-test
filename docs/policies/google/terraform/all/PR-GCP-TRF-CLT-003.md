



# Title: GCP Kubernetes Engine Clusters Client Certificate is set to Disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-003|
|eval|data.rule.k8s_client_cert|
|message|data.rule.k8s_client_cert_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
