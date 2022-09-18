



# Title: Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-PSQL-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-PSQL-008|
|eval|data.rule.storage_psql_log_min_duration_statement|
|message|data.rule.storage_psql_log_min_duration_statement_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_min_duration_statement is not set to -1. The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged. Logging SQL statements may include sensitive information that should not be recorded in logs. So it is recommended to set  log_min_duration_statement flag value to -1 so that execution statements logging will be disabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST CSF', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
