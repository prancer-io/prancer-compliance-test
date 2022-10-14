



# Title: SQL DB instance backup configuration is not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-SQLI-003

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-SQLI-003|
|eval|data.rule.sql_backup|
|message|data.rule.sql_backup_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_SQLI_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the configuration for automated backups is enabled. <br>         Restoring from a backup reverts your instance to its state at the backup's creation time. Enabling automated backups creates backup during the scheduled backup window.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/sqladmin.rego
