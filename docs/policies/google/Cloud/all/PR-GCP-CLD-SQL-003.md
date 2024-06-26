



# Title: Ensure GCP SQL Instances contains Label information


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQL-003

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQL-003|
|eval|data.rule.storage_sql_label_info|
|message|data.rule.storage_sql_label_info_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQL_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the SQL DB instance which does not have any Labels. Labels can be used for easy identification and searches.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
