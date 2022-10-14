



# Title: Ensure GCP Log metric filter and alert exists for VPC Network Firewall rule changes


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-LOG-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([logging.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-LOG-006|
|eval|data.rule.logging_vpc_firewall|
|message|data.rule.logging_vpc_firewall_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies the GCP accounts which do not have a log metric filter and alert for VPC Network Firewall rule changes. Monitoring for Create or Update firewall rule events gives insight network access changes and may reduce the time it takes to detect suspicious activity. It is recommended to create a metric filter and alarm to detect VPC Network Firewall rule changes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'CIS', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_logging_metric']


[logging.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/logging.rego
