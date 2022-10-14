



# Title: Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-PSQL-004

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-PSQL-004|
|eval|data.rule.storage_psql_log_error_verbosity|
|message|data.rule.storage_psql_log_error_verbosity_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_PSQL_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_error_verbosity is not set to default. The flag log_error_verbosity controls the amount of detail written in the server log for each message that is logged. Valid values are TERSE, DEFAULT, and VERBOSE. It is recommended to set log_error_verbosity to default or terse.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
