



# Title: GCP VM instances have block project-wide SSH keys feature disabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-INST-002

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_INSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-INST-002|
|eval|data.rule.vm_block_project_ssh_keys|
|message|data.rule.vm_block_project_ssh_keys_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_INST_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies VM instances which have block project-wide SSH keys feature disabled. Project-wide SSH keys are stored in Compute/Project-metadata. Project-wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within a project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CIS']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
