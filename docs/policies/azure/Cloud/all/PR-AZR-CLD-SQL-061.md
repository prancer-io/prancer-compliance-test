



# Title: Ensure Azure MySQL Server has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-061

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_411']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-061|
|eval|data.rule.mysql_server_latest_tls_configured|
|message|data.rule.mysql_server_latest_tls_configured_err|
|remediationDescription|Follow these steps to set MySQL server minimum TLS version:<br><br>1. In the Azure portal, select your existing Azure Database for MySQL server.<br>2. On the MySQL server page, under Settings, click Connection security to open the connection security configuration page.<br>3. In Minimum TLS version, select 1.2 to deny connections with TLS version less than TLS 1.2 for your MySQL server.<br>4. Click Save to save the changes.<br>5. A notification will confirm that connection security setting was successfully enabled and in effect immediately. There is no restart of the server required or performed. After the changes are saved, all new connections to the server are accepted only if the TLS version is greater than or equal to the minimum TLS version set on the portal.|
|remediationFunction|PR_AZR_CLD_SQL_061.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure MySQL Server which doesn't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMySQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMySQL.rego
