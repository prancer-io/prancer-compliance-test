



# Title: Ensure GCP SQL server instance database flag user options is not set


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQL-012

***<font color="white">Master Snapshot Id:</font>*** ['INST_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQL-012|
|eval|data.rule.storage_sql_user_option|
|message|data.rule.storage_sql_user_option_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_INST_SQL_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies GCP SQL server instances fo which database flag user options is set. The user options option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. A user can override these defaults by using the SET statement. It is recommended that, user options database flag for SQL Server instance should not be configured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
