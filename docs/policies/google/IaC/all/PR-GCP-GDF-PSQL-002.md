



# Title: Ensure GCP PostgreSQL instance database flag log_disconnections is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PSQL-002

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PSQL-002|
|eval|data.rule.storage_psql_log_disconnections|
|message|data.rule.storage_psql_log_disconnections_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PSQL_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL type SQL instances for which the log_disconnections database flag is disabled. Enabling the log_disconnections setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
