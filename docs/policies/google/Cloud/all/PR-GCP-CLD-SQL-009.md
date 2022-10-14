



# Title: Ensure GCP SQL server instance database flag external scripts enabled is set to off


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQL-009

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQL-009|
|eval|data.rule.storage_sql_external_script|
|message|data.rule.storage_sql_external_script_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQL_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP SQL server instances for which database flag 'external scripts enabled' is not set to off. Feature 'external scripts enabled' enables the execution of scripts with certain remote language extensions. When Advanced Analytics Services is installed, setup can optionally set this property to true. As the External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed, which could adversely affect the security of the system. It is recommended to set external scripts enabled database flag for Cloud SQL SQL Server instance to off.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
