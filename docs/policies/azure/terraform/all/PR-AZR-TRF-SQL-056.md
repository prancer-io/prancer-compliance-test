



# Master Test ID: PR-AZR-TRF-SQL-056


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mariadb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-056|
|eval|data.rule.mairadb_ssl_enforcement_enabled|
|message|data.rule.mairadb_ssl_enforcement_enabled_err|
|remediationDescription|In 'azurerm_mariadb_server' resource, set 'ssl_enforcement_enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_056.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure ssl enforcement is enabled on MariaDB Server.

***<font color="white">Description:</font>*** Enable SSL connection on MariaDB Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mariadb_firewall_rule', 'azurerm_mariadb_server']


[mariadb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
