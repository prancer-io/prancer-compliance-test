



# Title: SQL managedInstances should be integrated with Azure Active Directory for administration


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-003

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_401']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbadministrators.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-003|
|eval|data.rule.sql_managedinstances_ad_admin|
|message|data.rule.sql_managedinstances_ad_admin_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/aad-security-configure-tutorial' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that SQL managedInstances are configured with Active Directory admin authentication. Azure Active Directory (Azure AD) authentication is a mechanism for connecting to Azure SQL Database, Azure SQL Managed Instance, and Synapse SQL in Azure Synapse Analytics by using identities in Azure AD. With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location. Central ID management provides a single place to manage database users and simplifies permission management.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['Databases']|



[dbadministrators.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbadministrators.rego
