



# Title: GCP Storage bucket encrypted using default KMS key instead of a customer-managed key


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-BKT-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-BKT-001|
|eval|data.rule.storage_encrypt|
|message|data.rule.storage_encrypt_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_BKT_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Storage buckets that are encrypted with the default Google-managed keys. As a best practice, use Customer-managed key to encrypt the data in your storage bucket and ensure full control over your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['storage.v1.bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/storage.rego
