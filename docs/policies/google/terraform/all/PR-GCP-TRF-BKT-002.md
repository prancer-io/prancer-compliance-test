



# Title: GCP Storage log buckets have object versioning disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BKT-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.v1.bucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BKT-002|
|eval|data.rule.storage_versioning|
|message|data.rule.storage_versioning_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Storage log buckets which have object versioning disabled. Enabling object versioning on storage log buckets will protect your cloud storage data from being overwritten or accidentally deleted. It is recommended to enable object versioning feature on all storage buckets where sinks are configured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_storage_bucket']


[storage.v1.bucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/storage.v1.bucket.rego
