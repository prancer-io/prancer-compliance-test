



# Master Test ID: PR-AZR-TRF-SQL-061


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mysql_server.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-061|
|eval|data.rule.mysql_server_latest_tls_configured|
|message|data.rule.mysql_server_latest_tls_configured_err|
|remediationDescription|In 'azurerm_mysql_server' resource, set ssl_minimal_tls_version_enforced = 'TLS1_2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_061.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Azure MySQL Server has latest version of tls configured

***<font color="white">Description:</font>*** This policy will identify the Azure MySQL Server which dont have latest version of tls configured and give alert  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mysql_firewall_rule', 'azurerm_mysql_server']


[mysql_server.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mysql_server.rego
