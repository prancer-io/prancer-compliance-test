



# Title: Ensure MariaDB servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-057

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_409']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-057|
|eval|data.rule.mairadb_public_access_disabled|
|message|data.rule.mairadb_public_access_disabled_err|
|remediationDescription|Follow these steps to set MariaDB server Deny Public Network Access:<br><br>1. In the Azure portal, select your existing Azure Database for MariaDB server.<br>2. On the MariaDB server page, under Settings, click Connection security to open the connection security configuration page.<br>3. In Deny Public Network Access, select Yes to enable deny public access for your MariaDB server.<br>4. Click Save to save the changes.<br>5. A notification will confirm that connection security setting was successfully enabled.|
|remediationFunction|PR_AZR_CLD_SQL_057.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for MariaDB Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMariaDB.rego
