



# Title: Ensure GCP SQL server instance database flag user connections is set


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQL-011

***<font color="white">Master Snapshot Id:</font>*** ['INST_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQL-011|
|eval|data.rule.storage_sql_user_connection|
|message|data.rule.storage_sql_user_connection_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_INST_SQL_011.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies GCP SQL server instances where the database flag 'user connections' is not set. The user connections option specifies the maximum number of simultaneous user connections (value varies in range 10-32,767) that are allowed on an instance of SQL Server. The default is 0, which means that the maximum (32,767) user connections are allowed. It is recommended to set database flag user connections for SQL Server instance according to organization-defined value.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
