



# Title: GCP Firewall rule allows internet traffic to SMTP port (25)


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-FW-013

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-FW-013|
|eval|data.rule.firewall_port_25|
|message|data.rule.firewall_port_25_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/firewalls' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_FW_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Firewall rules which allows inbound traffic on SMTP port (25) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.firewall']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
