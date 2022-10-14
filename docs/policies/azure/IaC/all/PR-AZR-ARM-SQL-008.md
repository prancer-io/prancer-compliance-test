



# Title: Azure SQL databases should have transparent data encryption enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-008

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbdataencryption.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-008|
|eval|data.rule.db_logical_encrypt|
|message|data.rule.db_logical_encrypt_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption' target='_blank'>here</a>. status should be Enabled|
|remediationFunction|PR_AZR_ARM_SQL_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchanges log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/transparentdataencryption']


[dbdataencryption.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbdataencryption.rego
