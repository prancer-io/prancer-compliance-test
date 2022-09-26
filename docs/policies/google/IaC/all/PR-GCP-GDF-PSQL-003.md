



# Title: Ensure GCP PostgreSQL instance database flag log_duration is set to on


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PSQL-003

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PSQL-003|
|eval|data.rule.storage_psql_log_duration|
|message|data.rule.storage_psql_log_duration_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PSQL_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_duration is not set to on. Enabling the log_duration setting causes the duration of each completed statement to be logged. Monitoring the time taken to execute the queries can be crucial in identifying any resource-hogging queries and assessing the performance of the server. Further steps such as load balancing and the use of optimized queries can be taken to ensure the performance and stability of the server. It is recommended to set log_duration as on.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
