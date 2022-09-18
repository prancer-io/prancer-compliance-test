



# Title: GCP Firewall rule allows internet traffic to DNS port (53)


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-FW-002

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_FIREWALL']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-FW-002|
|eval|data.rule.firewall_port_53|
|message|data.rule.firewall_port_53_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/firewalls' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_FW_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP Firewall rules which allows inbound traffic on DNS port (53) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['GDPR', 'CSA-CCM', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
