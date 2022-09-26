



# Title: Ensure GCP storage bucket is not logging to itself


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-BKT-008

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-BKT-008|
|eval|data.rule.storage_logging_itself|
|message|data.rule.storage_logging_itself_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_BKT_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies GCP storage buckets that are sending logs to themselves. When storage buckets use the same bucket to send their access logs, a loop of logs will be created, which is not a security best practice. It is recommended to spin up new and different log buckets for storage bucket logging.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['storage.v1.bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/storage.rego
