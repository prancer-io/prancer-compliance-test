



# Title: Ensure GCP GCE Disk snapshot is encrypted with CSEK


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-INST-008

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_INSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-INST-008|
|eval|data.rule.compute_disk_csek|
|message|data.rule.compute_disk_csek_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_INST_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP GCE Disk snapshots that are not encrypted with CSEK. It is recommended that to avoid data leakage provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. Only users who can provide the correct key can use resources protected by a customer-supplied encryption key  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
