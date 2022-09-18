



# Title: Ensure GCP PostgreSQL instance database flag log_temp_files is set to 0


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PSQL-014

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PSQL-014|
|eval|data.rule.storage_psql_log_temp_files|
|message|data.rule.storage_psql_log_temp_files_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PSQL_014.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_temp_files is not set to 0. The log_temp_files flag controls the logging of names and size of temporary files. Configuring log_temp_files to 0 causes all temporary file information to be logged, while positive values log only files whose size is greater than or equal to the specified number of kilobytes. A value of -1 disables temporary file information logging. If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be either poor application coding or deliberate resource starvation attempts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
