



# Title: SQL servers should be integrated with Azure Active Directory for administration


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_400']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbadministrators.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-001|
|eval|data.rule.sql_server_ad_admin|
|message|data.rule.sql_server_ad_admin_err|
|remediationDescription|In Azure Portal<br>1. Go to SQL servers<br>2. For each SQL server, click on Active Directory admin<br>3. Click on Set admin<br>4. Select an admin<br>5. Click Save<br><br>Default Value:<br>Azure Active Directory Authentication for SQL Database/Server is not enabled by default<br>References:<br><a href='https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure' target='_blank'>1. https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure</a><br><a href='https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication' target='_blank'>2. https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication</a>|
|remediationFunction|PR_AZR_CLD_SQL_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory (Azure AD) authentication is a mechanism for connecting to Azure SQL Database, Azure SQL Managed Instance, and Synapse SQL in Azure Synapse Analytics by using identities in Azure AD. With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location. Central ID management provides a single place to manage database users and simplifies permission management.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-IM-1', 'Azure Security Benchmark (v2)-PA-1', 'Azure Security Benchmark (v3)-GS-6', 'Brazilian Data Protection Law (LGPD)-Article 46', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-4.19', 'CIS v1.1 (Azure)-4.8', 'CIS v1.2.0 (Azure)-4.4', 'CIS v1.3.0 (Azure)-4.4', 'CIS v1.3.1 (Azure)-4.4', 'CIS v1.4.0 (Azure)-4.5', 'CSA CCM', 'CSA CCM v3.0.1-DCS-01', 'CSA CCM v3.0.1-DSI-06', 'CSA CCM v3.0.1-EKM-01', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IAM-02', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-04', 'CSA CCM v3.0.1-IAM-05', 'CSA CCM v3.0.1-IAM-08', 'CSA CCM v3.0.1-IAM-09', 'CSA CCM v3.0.1-IAM-10', 'CSA CCM v3.0.1-IAM-11', 'CSA CCM v3.0.1-IAM-12', 'CSA CCM v3.0.1-IAM-13', 'CSA CCM v3.0.1-IVS-02', 'CSA CCM v3.0.1-IVS-11', 'CSA CCM v3.0.1-MOS-09', 'CSA CCM v3.0.1-MOS-16', "CyberSecurity Law of the People's Republic of China-Article 24", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.181', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.b', 'HITRUST CSF v9.3-Control Reference:01.d', 'HITRUST CSF v9.3-Control Reference:01.f', 'HITRUST CSF v9.3-Control Reference:01.q', 'HITRUST CSF v9.3-Control Reference:01.r', 'ISO 27001:2013', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.9.2.5', 'NIST 800', 'NIST 800-53 Rev4-AC-2 (7)(a)', 'NIST 800-53 Rev4-CM-8 (4)', 'NIST 800-53 Rev4-IA-5d', 'NIST CSF', 'NIST CSF-PR.AC-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.1.2e', 'PCI DSS', 'PCI DSS v3.2.1-8.7', 'PIPEDA', 'PIPEDA-4.7.3', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.2', 'SOC 2-CC6.3', 'SOC 2-CC8.1']|
|service|['Databases']|



[dbadministrators.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbadministrators.rego
