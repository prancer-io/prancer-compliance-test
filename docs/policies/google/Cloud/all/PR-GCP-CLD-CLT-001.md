



# Title: Ensure Kubernetes Engine Cluster Nodes have default Service account for Project access in Goole Cloud Provider.


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-001|
|eval|data.rule.k8s_svc_account|
|message|data.rule.k8s_svc_account_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'HITRUST', 'HIPAA', 'CIS', 'SOC 2']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
