



# Title: GCP Firewall rule allows internet traffic to SSH port (22)


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-FW-014

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-FW-014|
|eval|data.rule.firewall_port_22|
|message|data.rule.firewall_port_22_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/firewalls' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_FW_014.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies GCP Firewall rules which allows inbound traffic on SSH port (22) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'CIS', 'CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.firewall']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
