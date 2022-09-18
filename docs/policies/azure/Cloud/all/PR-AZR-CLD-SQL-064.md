



# Title: Ensure MariaDB Server is using latest TLS version.


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-064

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_409']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-064|
|eval|data.rule.mairadb_usage_latest_tls|
|message|data.rule.mairadb_usage_latest_tls_err|
|remediationDescription|Using the Azure portal, visit your Azure Database for MariaDB server, and then click Connection security. In Minimum TLS version, select 1.2 to deny connections with TLS version less than TLS 1.2 for your MariaDB server, and then click Save.|
|remediationFunction|PR_AZR_CLD_SQL_064.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Azure MariaDB database servers that are not using the latest TLS version for SSL enforcement. Azure Database for MariaDB uses Transport Layer Security (TLS) from communication with client applications. As a best security practice, use the newer TLS version as the minimum TLS version for the MariaDB database server. Currently, Azure MariaDB supports TLS 1.2 version which resolves the security gap from its preceding versions.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMariaDB.rego
