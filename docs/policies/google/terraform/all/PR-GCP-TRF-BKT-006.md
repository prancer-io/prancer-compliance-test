



# Title: Ensure cloud storage bucket with uniform bucket-level access enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BKT-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.v1.bucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BKT-006|
|eval|data.rule.storage_uniform_bucket_access|
|message|data.rule.storage_uniform_bucket_access_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_storage_bucket']


[storage.v1.bucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/storage.v1.bucket.rego
