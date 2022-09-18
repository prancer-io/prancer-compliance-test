



# Title: Default Firewall rule should not have any rules (except http and https)


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-FW-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.firewall.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-FW-001|
|eval|data.rule.firewall_default|
|message|data.rule.firewall_default_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Checks to ensure that the default Firewall rule should not have any (non http, https) rules. The default Firewall rules will apply all instances by default in the absence of specific custom rules with higher priority. It is a safe practice to not have these rules in the default Firewall.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_firewall']


[compute.v1.firewall.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.firewall.rego
