



# Title: Ensure GCP Kubernetes cluster node auto-upgrade configuration enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-031

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-031|
|eval|data.rule.k8s_node_autoupgrade|
|message|data.rule.k8s_node_autoupgrade_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a> |
|remediationFunction|PR_GCP_TRF_CLT_031.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Kubernetes cluster nodes with auto-upgrade configuration disabled. Node auto-upgrades help you keep the nodes in your cluster up to date with the cluster master version when your master is updated on your behalf. When you create a new cluster using Google Cloud Platform Console, node auto-upgrade is enabled by default.

FMI: https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
