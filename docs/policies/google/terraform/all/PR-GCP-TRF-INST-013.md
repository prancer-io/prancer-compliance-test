



# Title: Ensure GCP VM instance with Shielded VM features enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-INST-013

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.instance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-INST-013|
|eval|data.rule.compute_shielded_vm|
|message|data.rule.compute_shielded_vm_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_TRF_INST_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies VM instances which have Shielded VM features disabled. Shielded VMs are virtual machines (VMs) on Google Cloud Platform hardened by a set of security controls that help defend against rootkits and bootkits. Shielded VM's verifiable integrity is achieved through the use of Secure Boot, virtual trusted platform module (vTPM)-enabled Measured Boot, and integrity monitoring. Shielded VM instances run firmware which is signed and verified using Google's Certificate Authority, ensuring that the instance's firmware is unmodified and establishing the root of trust for Secure Boot.

NOTE: You can only enable Shielded VM options on instances that have Shielded VM support. This policy reports VM instances that have Shielded VM support and are disabled with the Shielded VM features.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_instance']


[compute.v1.instance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.instance.rego
