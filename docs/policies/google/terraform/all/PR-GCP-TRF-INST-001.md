



# Title: GCP VM instances have IP forwarding enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-INST-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.instance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-INST-001|
|eval|data.rule.vm_ip_forward|
|message|data.rule.vm_ip_forward_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies VM instances have IP forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable source and destination IP match check, disable the IP Forwarding.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CIS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_instance']


[compute.v1.instance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.instance.rego
