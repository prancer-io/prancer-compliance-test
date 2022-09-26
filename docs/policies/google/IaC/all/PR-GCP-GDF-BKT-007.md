



# Title: Ensure GCP storage bucket is configured with default Event-Based hold


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-BKT-007

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-BKT-007|
|eval|data.rule.storage_event_based_hold|
|message|data.rule.storage_event_based_hold_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_BKT_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies GCP storage buckets that are not configured with default Event-Based Hold. An event-based hold resets the object's time in the bucket for the purposes of the retention period. This behavior is useful when you want an object to persist in your bucket for a certain length of time after a certain event occurs. It is recommended to enable this feature to protect individual objects from deletion.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['storage.v1.bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/storage.rego
