



# Title: Ensure GCP VM instance not have the external IP address


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-INST-014

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_INSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-INST-014|
|eval|data.rule.compute_instance_external_ip|
|message|data.rule.compute_instance_external_ip_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_INST_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the VM instances with the external IP address associated. To reduce your attack surface, VM instances should not have public/external IP addresses. Instead, instances should be configured behind load balancers, to minimize the instance's exposure to the internet.

NOTE: This policy will not report instances created by GKE because some of them have external IP addresses and cannot be changed by editing the instance settings. Instances created by GKE should be excluded. These instances have names that start with 'gke-' and contains 'default-pool'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
