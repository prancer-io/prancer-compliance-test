



# Title: Ensure ssl enforcement is enabled on MariaDB Server.


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-056

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-056|
|eval|data.rule.mairadb_ssl_enforcement_enabled|
|message|data.rule.mairadb_ssl_enforcement_enabled_err|
|remediationDescription|In 'microsoft.dbformariadb/servers' resource, set 'sslEnforcement = Enabled' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_056.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable SSL connection on MariaDB Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformariadb/servers']


[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMariaDB.rego
