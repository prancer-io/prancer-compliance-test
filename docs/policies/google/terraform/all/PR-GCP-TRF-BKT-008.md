



# Title: Ensure GCP storage bucket is not logging to itself


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BKT-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.v1.bucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BKT-008|
|eval|data.rule.storage_logging_itself|
|message|data.rule.storage_logging_itself_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies GCP storage buckets that are sending logs to themselves. When storage buckets use the same bucket to send their access logs, a loop of logs will be created, which is not a security best practice. It is recommended to spin up new and different log buckets for storage bucket logging.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_storage_bucket']


[storage.v1.bucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/storage.v1.bucket.rego
