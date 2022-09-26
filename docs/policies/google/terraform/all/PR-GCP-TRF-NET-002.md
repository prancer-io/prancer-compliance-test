



# Title: GCP project is using the default network


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-NET-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.network.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-NET-002|
|eval|data.rule.net_default|
|message|data.rule.net_default_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'HITRUST']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_project']


[compute.v1.network.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.network.rego
