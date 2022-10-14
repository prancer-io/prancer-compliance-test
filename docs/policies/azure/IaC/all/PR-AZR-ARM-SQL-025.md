



# Title: Azure SQL Server advanced data security should have email alert recipient to get scan notification


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-025

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbvulnerabilityassessments.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-025|
|eval|data.rule.db_logical_ads_mail|
|message|data.rule.db_logical_ads_mail_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL Server by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments' target='_blank'>here</a>. Specifies an array of e-mail addresses to which the scan notification is sent.|
|remediationFunction|PR_AZR_ARM_SQL_025.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL Servers that do not have an email address configured for ADS alert notifications. As a best practice, provide one or more email addresses where you want to receive alerts for any anomalous activities detected on SQL Servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/vulnerabilityassessments']


[dbvulnerabilityassessments.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbvulnerabilityassessments.rego
