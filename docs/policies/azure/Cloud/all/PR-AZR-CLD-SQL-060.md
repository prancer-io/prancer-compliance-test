



# Title: Ensure MySQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-060

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_411']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-060|
|eval|data.rule.mysql_public_access_disabled|
|message|data.rule.mysql_public_access_disabled_err|
|remediationDescription|Follow these steps to set MySQL server Deny Public Network Access:<br><br>1. In the Azure portal, select your existing Azure Database for MySQL server.<br>2. On the MySQL server page, under Settings, click Connection security to open the connection security configuration page.<br>3. In Deny Public Network Access, select Yes to enable deny public access for your MySQL server.<br>4. Click Save to save the changes.<br>5. A notification will confirm that connection security setting was successfully enabled.|
|remediationFunction|PR_AZR_CLD_SQL_060.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for Azure MySQL Database Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMySQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMySQL.rego
