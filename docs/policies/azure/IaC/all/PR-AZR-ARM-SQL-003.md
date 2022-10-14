



# Title: SQL managedInstances should be integrated with Azure Active Directory for administration


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-003

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbadministrators.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-003|
|eval|data.rule.sql_managedinstances_ad_admin|
|message|data.rule.sql_managedinstances_ad_admin_err|
|remediationDescription|Make sure you are following the ARM template guidelines for SQL managedInstances by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/administrators?tabs=json' target='_blank'>here</a>. administratorType should be ActiveDirectory|
|remediationFunction|PR_AZR_ARM_SQL_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that SQL managedInstances are configured with Active Directory admin authentication. Azure Active Directory (Azure AD) authentication is a mechanism for connecting to Azure SQL Database, Azure SQL Managed Instance, and Synapse SQL in Azure Synapse Analytics by using identities in Azure AD. With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location. Central ID management provides a single place to manage database users and simplifies permission management.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.sql/servers', 'microsoft.sql/managedinstances/administrators', 'microsoft.sql/servers/administrators']


[dbadministrators.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbadministrators.rego
