



# Title: Ensure GCP Log bucket retention policy is configured using bucket lock


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BKT-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.v1.bucket.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BKT-009|
|eval|data.rule.storage_bucket_lock|
|message|data.rule.storage_bucket_lock_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP log buckets for which retention policy is not configured using bucket lock. It is recommended to configure the data retention policy for cloud storage buckets using bucket lock to permanently prevent the policy from being reduced or removed in case the system is compromised by an attacker or a malicious insider.

Note: Locking a bucket is an irreversible action. Once you lock a bucket, you cannot remove the retention policy from the bucket or decrease the retention period for the policy.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_storage_bucket']


[storage.v1.bucket.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/storage.v1.bucket.rego
