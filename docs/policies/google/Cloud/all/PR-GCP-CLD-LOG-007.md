



# Title: GCP Log metric filter and alert exists for VPC network changes


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-LOG-007

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_LOGGING']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([logging.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-LOG-007|
|eval|data.rule.logging_vpc_network|
|message|data.rule.logging_vpc_network_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_LOG_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the GCP account which does not have a log metric filter and alert for VPC network changes. Monitoring network insertion, patching, deletion, removePeering and addPeering activities will help in identifying VPC traffic flow is not getting impacted. It is recommended to create a metric filter and alarm to detect activities related to the insertion, patching, deletion, removePeering and addPeering of VPC network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'CIS', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[logging.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/logging.rego
