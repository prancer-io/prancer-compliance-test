



# Title: Azure SQL Server advanced data security should send alerts to subscription administrators


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-059

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sql_vulnerabilityassessments.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-059|
|eval|data.rule.db_logical_ads_alert|
|message|data.rule.db_logical_ads_alert_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/vulnerabilityassessments?tabs=json' target='_blank'>here</a>. Specify admin e-mail address at recurringScans.emailSubscriptionAdmins property where the schedule scan notification would be sent.|
|remediationFunction|PR_AZR_ARM_SQL_059.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL Servers that are not enabled with ADS. As a best practice, enable ADS so that the subscription admin can receive email alerts when anomalous activities are detected on the SQL Servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/servers/vulnerabilityassessments']


[sql_vulnerabilityassessments.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_vulnerabilityassessments.rego
