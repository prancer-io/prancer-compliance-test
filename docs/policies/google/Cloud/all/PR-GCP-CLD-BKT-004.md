



# Title: Storage Bucket does not have Access and Storage Logging enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-BKT-004

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_STORAGE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-BKT-004|
|eval|data.rule.storage_logging|
|message|data.rule.storage_logging_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_BKT_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the configuration on the Storage Buckets is enabled for access logs and storage logs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|cloud|
|compliance|['GDPR', 'CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['storage']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/storage.rego
