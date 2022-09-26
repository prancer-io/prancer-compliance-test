



# Title: Ensure Azure SQL Server data replication with Fail Over groups


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-050

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_servers.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-050|
|eval|data.rule.fail_over_groups|
|message|data.rule.fail_over_groups_err|
|remediationDescription|For Resource type 'microsoft.sql/servers' make sure has a subresource with type 'failoverGroups'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups' target='_blank'>here</a> for more details.|
|remediationFunction|PR_AZR_ARM_SQL_050.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** SQL Server data should be replicated to avoid loss of unreplicated data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/administrators']


[sql_servers.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego
