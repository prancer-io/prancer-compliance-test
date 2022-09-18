



# Title: MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)


***<font color="white">Master Test Id:</font>*** PR-AZR-TRF-SQL-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([mariadb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-SQL-012|
|eval|data.rule.maria_ingress_from_any_ip_disabled|
|message|data.rule.maria_ingress_from_any_ip_disabled_err|
|remediationDescription|Make sure resource 'azurerm_mariadb_server' and 'azurerm_private_endpoint' or 'azurerm_mariadb_firewall_rule' exist and in 'azurerm_mariadb_firewall_rule' resource, make sure 'start_ip_address' and 'end_ip_address' dont have port range configured to '0.0.0.0' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_firewall_rule#start_ip_address' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_SQL_012.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_mariadb_firewall_rule', 'azurerm_mariadb_server']


[mariadb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/mariadb.rego
