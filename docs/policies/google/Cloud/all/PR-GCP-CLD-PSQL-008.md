



# Title: Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-PSQL-008

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-PSQL-008|
|eval|data.rule.storage_psql_log_min_duration_statement|
|message|data.rule.storage_psql_log_min_duration_statement_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_PSQL_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_min_duration_statement is not set to -1. The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged. Logging SQL statements may include sensitive information that should not be recorded in logs. So it is recommended to set  log_min_duration_statement flag value to -1 so that execution statements logging will be disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST CSF', 'NIST 800', 'PCI-DSS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
