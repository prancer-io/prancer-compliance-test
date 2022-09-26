



# Title: Azure SQL Server advanced data security recurring scans should be enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-022

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbvulnerabilityassessments.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-022|
|eval|data.rule.db_ads_scan|
|message|data.rule.db_ads_scan_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment?tabs=azure-powershell' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_022.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that do not have ADS enabled. As a best practice, enable ADS on mission-critical SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Databases']|



[dbvulnerabilityassessments.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbvulnerabilityassessments.rego
