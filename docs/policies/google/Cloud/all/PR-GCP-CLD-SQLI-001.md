



# Title: GCP SQL Instances without any Label information


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SQLI-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sqladmin.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SQLI-001|
|eval|data.rule.sql_labels|
|message|data.rule.sql_labels_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SQLI_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the SQL DB instance which does not have any Labels. Labels can be used for easy identification and searches.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[sqladmin.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/sqladmin.rego
