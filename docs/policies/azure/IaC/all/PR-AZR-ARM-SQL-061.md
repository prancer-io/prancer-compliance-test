



# Title: Ensure Azure MySQL Server has latest version of tls configured


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-061

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-061|
|eval|data.rule.mysql_server_latest_tls_configured|
|message|data.rule.mysql_server_latest_tls_configured_err|
|remediationDescription|In 'microsoft.dbformysql/servers' resource, set minimalTlsVersion = 'TLS1_2' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_061.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy will identify the Azure MySQL Server which doesn't have the latest version of tls configured and give the alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformysql/servers']


[dbforMySQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMySQL.rego
