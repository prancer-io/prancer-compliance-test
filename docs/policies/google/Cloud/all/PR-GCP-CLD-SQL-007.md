



# Title: Ensure GCP SQL database is not assigned with public IP


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQL-007

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQL-007|
|eval|data.rule.storage_sql_public_ip|
|message|data.rule.storage_sql_public_ip_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQL_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP SQL databases which are assigned with public IP.  To lower the organisation's attack surface, Cloud SQL databases should not have public IPs. Private IPs provide improved network security and lower latency for your application. It is recommended to configure Second Generation Sql instance to use private IPs instead of public IPs.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
