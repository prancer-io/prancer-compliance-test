



# Title: Ensure GCP PostgreSQL instance with log_checkpoints database flag is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PSQL-015

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PSQL-015|
|eval|data.rule.storage_psql_log_checkpoints|
|message|data.rule.storage_psql_log_checkpoints_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PSQL_015.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL instances in which log_checkpoints database flag is not set. Enabling the log_checkpoints database flag would enable logging of checkpoints and restart points to the server log.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
