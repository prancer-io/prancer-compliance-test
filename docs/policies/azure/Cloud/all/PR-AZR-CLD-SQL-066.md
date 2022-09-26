



# Title: Ensure PostgreSQL servers don't have public network access enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-066

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_412']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-066|
|eval|data.rule.postgresql_public_access_disabled|
|message|data.rule.postgresql_public_access_disabled_err|
|remediationDescription|1. In the Azure portal, select your existing Azure Database for PostgreSQL Single server.<br>2. On the PostgreSQL Single server page, under Settings, click Connection security to open the connection security configuration page.<br>3. In Deny Public Network Access, select Yes to enable deny public access for your PostgreSQL Single server.<br>4. Click Save to save the changes.<br>5. A notification will confirm that connection security setting was successfully enabled.|
|remediationFunction|PR_AZR_CLD_SQL_066.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Always use Private Endpoint for PostgreSQL Server  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/postgreSQL.rego
