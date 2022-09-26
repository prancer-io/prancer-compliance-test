



# Title: SQL Instances with network authorization exposing them to the Internet


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQLI-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQLI-005|
|eval|data.rule.sql_exposed|
|message|data.rule.sql_exposed_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the SQL instance should not have any authorization to allow network traffic to the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/sqladmin.rego
