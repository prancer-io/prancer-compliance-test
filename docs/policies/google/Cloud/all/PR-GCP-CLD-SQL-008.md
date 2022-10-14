



# Title: Ensure GCP SQL instance is not configured with overly permissive authorized networks


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQL-008

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQL-008|
|eval|data.rule.storage_sql_overly_permissive|
|message|data.rule.storage_sql_overly_permissive_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQL_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Cloud SQL instances that are configured with overly permissive authorized networks. You can connect to the SQL instance securely by using the Cloud SQL Proxy or adding your client's public address as an authorized network. If your client application is connecting directly to a Cloud SQL instance on its public IP address, you have to add your client's external address as an Authorized network for securing the connection. It is recommended to add specific IPs instead of public IPs as authorized networks as per the requirement.

Reference: https://cloud.google.com/sql/docs/mysql/authorize-networks  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
