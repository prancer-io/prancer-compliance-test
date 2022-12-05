



# Title: GCP VPC Network subnets have Private Google access not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-SUBN-002

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SUBNETWORKS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-SUBN-002|
|eval|data.rule.vpc_private_ip_google|
|message|data.rule.vpc_private_ip_google_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_SUBN_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'SOC 2']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
