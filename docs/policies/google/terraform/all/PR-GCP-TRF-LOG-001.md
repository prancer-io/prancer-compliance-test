



# Title: Ensure GCP Log metric filter and alert exists for Audit Configuration Changes


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-LOG-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([logging.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-LOG-001|
|eval|data.rule.logging_audit_config|
|message|data.rule.logging_audit_config_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the GCP accounts which do not have a log metric filter and alert for Audit Configuration Changes. Configuring metric filter and alerts for Audit Configuration Changes ensures recommended state of audit configuration and hence, all the activities in project are audit-able at any point in time.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'CIS', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_logging_metric']


[logging.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/logging.rego
