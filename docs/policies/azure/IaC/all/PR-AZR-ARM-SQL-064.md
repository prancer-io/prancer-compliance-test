



# Title: Ensure MariaDB Server is using latest TLS version.


***<font color="white">Master Test Id:</font>*** PR-AZR-ARM-SQL-064

***<font color="white">Master Snapshot Id:</font>*** ['ARM_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-ARM-SQL-064|
|eval|data.rule.mairadb_usage_latest_tls|
|message|data.rule.mairadb_usage_latest_tls_err|
|remediationDescription|In 'microsoft.dbformariadb/servers' resource, set 'minimalTlsVersion = TLS1_2' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_ARM_SQL_064.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies Azure MariaDB database servers that are not using the latest TLS version for SSL enforcement. Azure Database for MariaDB uses Transport Layer Security (TLS) from communication with client applications. As a best security practice, use the newer TLS version as the minimum TLS version for the MariaDB database server. Currently, Azure MariaDB supports TLS 1.2 version which resolves the security gap from its preceding versions.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['arm']|


***<font color="white">Resource Types:</font>*** ['microsoft.dbformariadb/servers']


[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/dbforMariaDB.rego
