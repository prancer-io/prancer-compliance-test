



# Title: Azure SQL databases should have transparent data encryption enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-009

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbdataencryption.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-009|
|eval|data.rule.db_encrypt|
|message|data.rule.db_encrypt_err|
|remediationDescription|1. Go to 'SQL databases' and choose your database<br>2. Select 'Transparent data encryption' under 'Security' in the navigation menu<br>3. Set 'Data encryption' to 'On'<br>4. Save|
|remediationFunction|PR_AZR_CLD_SQL_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchanges log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Databases']|



[dbdataencryption.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbdataencryption.rego
