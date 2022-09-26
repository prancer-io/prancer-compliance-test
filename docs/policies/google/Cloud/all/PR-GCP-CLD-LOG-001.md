



# Title: Ensure GCP Log metric filter and alert exists for Audit Configuration Changes


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-LOG-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_LOGGING']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([logging.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-LOG-001|
|eval|data.rule.logging_audit_config|
|message|data.rule.logging_audit_config_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_LOG_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the GCP accounts which do not have a log metric filter and alert for Audit Configuration Changes. Configuring metric filter and alerts for Audit Configuration Changes ensures recommended state of audit configuration and hence, all the activities in project are audit-able at any point in time.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'CIS', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[logging.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/logging.rego
