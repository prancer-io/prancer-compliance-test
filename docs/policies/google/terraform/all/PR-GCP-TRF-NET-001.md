



# Title: Ensure, GCP project is configured with legacy network


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-NET-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.network.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-NET-001|
|eval|data.rule.net_legacy|
|message|data.rule.net_legacy_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'HITRUST']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_network']


[compute.v1.network.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.network.rego
