



# Title: Storage Bucket does not have Access and Storage Logging enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BKT-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.v1.bucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BKT-004|
|eval|data.rule.storage_logging|
|message|data.rule.storage_logging_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the configuration on the Storage Buckets is enabled for access logs and storage logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_storage_bucket']


[storage.v1.bucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/storage.v1.bucket.rego
