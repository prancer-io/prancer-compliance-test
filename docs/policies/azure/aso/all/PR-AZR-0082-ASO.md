



# Master Test ID: TEST_DB_Firewallrules


***<font color="white">Master Snapshot Id:</font>*** ['ASO_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbfirewallrules.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-0082-ASO|
|eval|data.rule.db_firewall|
|message|data.rule.db_firewall_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** SQL Server Firewall rules allow access to any Azure internal resources

***<font color="white">Description:</font>*** Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['aso']|


***<font color="white">Resource Types:</font>*** ['azuresqlfirewallrule']


[dbfirewallrules.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/aso/dbfirewallrules.rego
