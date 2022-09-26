



# Title: Ensure GCP MySQL instance with local_infile database flag is not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-SQL-002

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-SQL-002|
|eval|data.rule.storage_sql_local_infile|
|message|data.rule.storage_sql_local_infile_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_SQL_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies MySQL instances in which local_infile database flag is not disabled. The local_infile flag controls the server-side LOCAL capability for LOAD DATA statements. Based on the settings in local_infile server refuses or permits local data loading by clients. Disabling the local_infile flag setting, would disable the local data loading by clients that have LOCAL enabled on the client side.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
