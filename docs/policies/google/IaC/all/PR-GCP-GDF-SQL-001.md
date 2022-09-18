



# Title: Ensure GCP MySQL instance database flag skip_show_database is set to on


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-SQL-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-SQL-001|
|eval|data.rule.storage_sql_skip_show_database|
|message|data.rule.storage_sql_skip_show_database_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_SQL_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Mysql database instances in which database flag skip_show_database is not set to on. This prevents people from using the SHOW DATABASES statement if they do not have the SHOW DATABASES privilege. This can improve security if you have concerns about users being able to see databases belonging to other users. It is recommended to set skip_show_database to on.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
