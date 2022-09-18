



# Title: MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-015

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMySQL_firewallrules.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-015|
|eval|data.rule.my_logical_sql_ingress_from_any_ip_disabled|
|message|data.rule.my_logical_sql_ingress_from_any_ip_disabled_err|
|remediationDescription|For Resource type 'microsoft.dbformariadb/servers/firewallrules' make sure startIpAddress and endIpAddress exists and do not allow ingress from all Azure-internal IP addresses (0.0.0.0/0).<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers/firewallrules' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_015.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify MySQL Database Server firewall rule that is currently allowing ingress from all Azure-internal IP addresses  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformysql/servers', 'microsoft.dbformysql/servers/firewallrules']


[dbforMySQL_firewallrules.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMySQL_firewallrules.rego
