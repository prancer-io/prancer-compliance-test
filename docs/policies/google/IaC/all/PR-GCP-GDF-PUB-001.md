



# Title: Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PUB-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PUB-001|
|eval|data.rule.pub_sub_kms|
|message|data.rule.pub_sub_kms_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PUB_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.

Reference: https://cloud.google.com/pubsub/docs/encryption  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['pubsub.v1.topic']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/all.rego
