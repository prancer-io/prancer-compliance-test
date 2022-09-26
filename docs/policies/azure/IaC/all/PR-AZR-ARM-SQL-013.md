



# Title: MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-013

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-013|
|eval|data.rule.dbmaria_ingress_from_any_ip_disabled|
|message|data.rule.dbmaria_ingress_from_any_ip_disabled_err|
|remediationDescription|For Resource type 'microsoft.dbformariadb/servers/firewallrules' make sure startIpAddress and endIpAddress exists and do not allow ingress from all Azure-internal IP addresses (0.0.0.0/0).<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/2018-06-01/servers/firewallrules' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_013.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify MariaDB firewall rule that is currently allowing ingress from all Azure-internal IP addresses  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformariadb/servers', 'microsoft.dbformariadb/servers/firewallrules']


[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMariaDB.rego
