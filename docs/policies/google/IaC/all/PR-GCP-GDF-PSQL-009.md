



# Title: Ensure GCP PostgreSQL instance database flag log_min_messages is set


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-PSQL-009

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-PSQL-009|
|eval|data.rule.storage_psql_log_min_messages|
|message|data.rule.storage_psql_log_min_messages_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_PSQL_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_min_messages is not set. The log_min_messages flag controls which message levels are written to the server log, valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each level includes all the levels that follow it. log_min_messages flag value changes should only be made in accordance with the organization's logging policy. Auditing helps in troubleshooting operational problems and also permits forensic analysis.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST CSF', 'NIST 800', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['sqladmin.v1beta4.instance', 'gcp-types/sqladmin-v1beta4:instances']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/database.rego
