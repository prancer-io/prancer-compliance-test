



# Title: Ensure GCP PostgreSQL instance database flag log_lock_waits is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-PSQL-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-PSQL-007|
|eval|data.rule.storage_psql_log_lock_waits|
|message|data.rule.storage_psql_log_lock_waits_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_lock_waits is not set. Enabling the log_lock_waits flag can be used to identify poor performance due to locking delays or if a specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST CSF', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
