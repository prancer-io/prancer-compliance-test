



# Title: Ensure GCP Kubernetes Engine Clusters not have Legacy Authorization disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CLT-007

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CLT-007|
|eval|data.rule.k8s_legacy_abac|
|message|data.rule.k8s_legacy_abac_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CLT_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['container.v1.cluster']


[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/container.rego
