



# Title: GCP Kubernetes Engine Clusters not having any label information


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-021

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-021|
|eval|data.rule.k8s_labels|
|message|data.rule.k8s_labels_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_021.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
