



# Title: Ensure GCP Kubernetes Engine Clusters not have Master authorized networks enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-CLT-008

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_CLUSTER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-CLT-008|
|eval|data.rule.k8s_master_auth_net|
|message|data.rule.k8s_master_auth_net_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_CLT_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['container']|



[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/container.rego
