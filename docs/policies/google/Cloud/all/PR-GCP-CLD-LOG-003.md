



# Title: Ensure GCP Log metric filter and alert does exists for IAM custom role changes


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-LOG-003

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_LOGGING']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([logging.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-LOG-003|
|eval|data.rule.logging_iam_custom_permission_change|
|message|data.rule.logging_iam_custom_permission_change_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_LOG_003.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the GCP account which does not have a log metric filter and alert for IAM custom role changes. Monitoring role creation, deletion and updating activities will help in identifying over-privileged roles at early stages. It is recommended to create a metric filter and alarm to detect activities related to the creation, deletion and updating of custom IAM Roles.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'CIS', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[logging.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/logging.rego
