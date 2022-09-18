



# Title: Ensure GCP PostgreSQL instance database flag log_statement is set appropriately


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-PSQL-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-PSQL-012|
|eval|data.rule.storage_psql_log_statement|
|message|data.rule.storage_psql_log_statement_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_statement is not set appropriately. If log_statement is not set to a correct value may lead to too many statements or too few statements. Setting log_statement to align with your organization's security and logging policies facilitates later auditing and review of database activities. It is recommended to choose an appropriate value (ddl or mod) for the flag log_statement.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
