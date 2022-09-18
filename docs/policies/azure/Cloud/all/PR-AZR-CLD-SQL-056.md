



# Title: Ensure ssl enforcement is enabled on MariaDB Server.


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-056

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_409']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-056|
|eval|data.rule.mairadb_ssl_enforcement_enabled|
|message|data.rule.mairadb_ssl_enforcement_enabled_err|
|remediationDescription|Using the Azure portal, visit your Azure Database for MariaDB server, and then click Connection security. Use the toggle button to enable or disable the Enforce SSL connection setting, and then click Save. Microsoft recommends to always enable the Enforce SSL connection setting for enhanced security.|
|remediationFunction|PR_AZR_CLD_SQL_056.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable SSL connection on MariaDB Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMariaDB.rego
