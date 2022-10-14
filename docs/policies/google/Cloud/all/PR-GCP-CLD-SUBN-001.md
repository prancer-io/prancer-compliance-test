



# Title: GCP VPC Flow logs for the subnet is set to Off


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SUBN-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SUBNETWORKS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SUBN-001|
|eval|data.rule.vpc_flow_logs|
|message|data.rule.vpc_flow_logs_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SUBN_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'HITRUST']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
