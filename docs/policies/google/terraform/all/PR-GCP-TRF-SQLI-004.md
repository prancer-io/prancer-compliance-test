



# Title: SQL Instances do not have SSL configured


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SQLI-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SQLI-004|
|eval|data.rule.sql_ssl|
|message|data.rule.sql_ssl_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify that the SSL configuration for the SQL instance is valid with an unexpired SSL certificate.<br>         Cloud SQL supports connecting to an instance using the Secure Socket Layer (SSL) protocol. If you are not connecting to an instance by using Cloud SQL Proxy, you should use SSL, so that the data you send and receive from Google Cloud SQL is secure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_sql_database_instance']


[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/sqladmin.rego
