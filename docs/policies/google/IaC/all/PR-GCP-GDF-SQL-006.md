



# Title: Ensure GCP SQL database instance is configured with automated backups


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-SQL-006

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-SQL-006|
|eval|data.rule.storage_sql_automated_backup|
|message|data.rule.storage_sql_automated_backup_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_SQL_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP SQL Server instance database flag 'cross db ownership chaining' is enabled. Enabling cross db ownership is not recommended unless all of the databases hosted by the instance of SQL Server must participate in cross-database ownership chaining and you are aware of the security implications of this setting.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
