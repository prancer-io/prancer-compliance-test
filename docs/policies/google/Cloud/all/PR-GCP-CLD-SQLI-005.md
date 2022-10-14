



# Title: SQL Instances with network authorization exposing them to the Internet


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQLI-005

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQLI-005|
|eval|data.rule.sql_exposed|
|message|data.rule.sql_exposed_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instancess' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQLI_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the SQL instance should not have any authorization to allow network traffic to the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['cloud']|



[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/sqladmin.rego
