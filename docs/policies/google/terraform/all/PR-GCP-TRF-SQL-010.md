



# Title: Ensure GCP SQL server instance database flag remote access is set to off


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQL-010

***<font color="white">Master Snapshot Id:</font>*** ['INST_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQL-010|
|eval|data.rule.storage_sql_flag_remote|
|message|data.rule.storage_sql_flag_remote_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_INST_SQL_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP SQL server instances for which database flag remote access is not set to off. The remote access option controls the execution of stored procedures from local or remote servers on which instances of SQL Server are running. 'Remote access' functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target. It is recommended to set the remote access database flag for SQL Server instance to off.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
