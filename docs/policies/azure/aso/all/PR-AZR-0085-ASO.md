



# Master Test ID: TEST_DB_Administrators


***<font color="white">Master Snapshot Id:</font>*** ['ASO_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbadministrators.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-0085-ASO|
|eval|data.rule.db_ad_admin|
|message|data.rule.db_ad_admin_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** SQL servers which do not have Azure Active Directory admin configured

***<font color="white">Description:</font>*** Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['aso']|


***<font color="white">Resource Types:</font>*** ['mysqlserveradministrator']


[dbadministrators.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/aso/dbadministrators.rego
