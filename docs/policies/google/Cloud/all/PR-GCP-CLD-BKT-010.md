



# Title: Ensure GCP Log bucket retention policy is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-BKT-010

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_STORAGE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-BKT-010|
|eval|data.rule.storage_bucket_retention_enable|
|message|data.rule.storage_bucket_retention_enable_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_BKT_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP log buckets for which retention policy is not enabled. Enabling retention policies on log buckets will protect logs stored in cloud storage buckets from being overwritten or accidentally deleted. It is recommended to configure a data retention policy for these cloud storage buckets to store the activity logs for forensics and security investigations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|cloud|
|compliance|[]|
|service|['storage']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/storage.rego
