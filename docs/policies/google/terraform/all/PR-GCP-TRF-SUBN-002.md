



# Title: GCP VPC Network subnets have Private Google access not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-SUBN-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.subnetwork.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-SUBN-002|
|eval|data.rule.vpc_private_ip_google|
|message|data.rule.vpc_private_ip_google_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_subnetwork']


[compute.v1.subnetwork.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.subnetwork.rego
