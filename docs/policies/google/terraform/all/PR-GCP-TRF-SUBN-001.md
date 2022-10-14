



# Title: GCP VPC Flow logs for the subnet is set to Off


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SUBN-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.subnetwork.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SUBN-001|
|eval|data.rule.vpc_flow_logs|
|message|data.rule.vpc_flow_logs_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'HITRUST']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_subnetwork']


[compute.v1.subnetwork.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.subnetwork.rego
