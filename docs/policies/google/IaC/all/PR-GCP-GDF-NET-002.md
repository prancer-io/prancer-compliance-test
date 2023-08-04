



# Title: Ensure, GCP project is using the default network


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-NET-002

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-NET-002|
|eval|data.rule.net_default|
|message|data.rule.net_default_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/networks' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_NET_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'CIS', 'HITRUST']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.network']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
