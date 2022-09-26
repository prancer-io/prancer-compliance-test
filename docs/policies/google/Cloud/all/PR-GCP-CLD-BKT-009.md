



# Title: Ensure GCP Log bucket retention policy is configured using bucket lock


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-BKT-009

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_STORAGE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-BKT-009|
|eval|data.rule.storage_bucket_lock|
|message|data.rule.storage_bucket_lock_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_BKT_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP log buckets for which retention policy is not configured using bucket lock. It is recommended to configure the data retention policy for cloud storage buckets using bucket lock to permanently prevent the policy from being reduced or removed in case the system is compromised by an attacker or a malicious insider.

Note: Locking a bucket is an irreversible action. Once you lock a bucket, you cannot remove the retention policy from the bucket or decrease the retention period for the policy.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|cloud|
|compliance|[]|
|service|['storage']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/storage.rego
