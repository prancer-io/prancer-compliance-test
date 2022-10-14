



# Title: SQL DB Instance backup Binary logs configuration is not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQLI-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQLI-002|
|eval|data.rule.sql_binary_logs|
|message|data.rule.sql_binary_logs_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the configuration for automated backup of Binary logs is enabled.<br>Restoring from a backup reverts your instance to its state at the backup's creation time. Enabling automated backups creates backup during the scheduled backup window.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/sqladmin.rego
