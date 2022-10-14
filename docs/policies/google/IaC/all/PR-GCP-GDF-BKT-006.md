



# Title: Ensure cloud storage bucket with uniform bucket-level access enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-BKT-006

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-BKT-006|
|eval|data.rule.storage_uniform_bucket_access|
|message|data.rule.storage_uniform_bucket_access_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/storage/docs/json_api/v1/buckets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_BKT_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that Stackdriver logs on Storage Buckets are not public. Giving public access to Stackdriver logs will enable anyone with a web association to retrieve sensitive information that is critical to business. Stackdriver Logging enables to store, search, investigate, monitor and alert on log information/events from Google Cloud Platform. The permission needs to be set only for authorized users.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['storage.v1.bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/storage.rego
