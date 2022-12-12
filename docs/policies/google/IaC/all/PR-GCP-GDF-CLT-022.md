



# Title: GCP Kubernetes cluster Application-layer Secrets decrypted


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-CLT-022

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-CLT-022|
|eval|data.rule.k8s_db_encrypt|
|message|data.rule.k8s_db_encrypt_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_CLT_022.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd.<br><br> This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['container.v1.cluster']


[container.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/container.rego
