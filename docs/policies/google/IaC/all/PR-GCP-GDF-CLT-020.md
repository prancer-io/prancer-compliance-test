



# Title: GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CLT-020

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CLT-020|
|eval|data.rule.k8s_dashboard|
|message|data.rule.k8s_dashboard_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CLT_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Kubernetes Engine Clusters which have enabled Kubernetes web UI/Dashboard. Since all the data is being transmitted over HTTP protocol, disabling Kubernetes web UI/Dashboard will protect the data from sniffers on the same network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['container.v1.cluster']


[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/container.rego
