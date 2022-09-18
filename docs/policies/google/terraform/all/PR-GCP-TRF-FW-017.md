



# Title: GCP Firewall with Inbound rule overly permissive to All Traffic


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-FW-017

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.firewall.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-FW-017|
|eval|data.rule.firewall_inbound_all|
|message|data.rule.firewall_inbound_all_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies GCP Firewall rules which allows inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'GDPR', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_firewall']


[compute.v1.firewall.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.firewall.rego
