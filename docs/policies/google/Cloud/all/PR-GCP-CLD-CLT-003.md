



# Title: GCP Kubernetes Engine Clusters Client Certificate is set to Disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-003

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-003|
|eval|data.rule.k8s_client_cert|
|message|data.rule.k8s_client_cert_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
