



# Title: GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-DISK-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_DISKS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-DISK-001|
|eval|data.rule.disk_encrypt|
|message|data.rule.disk_encrypt_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/disks' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_DISK_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies VM disks which are not encrypted with Customer-Supplied Encryption Keys (CSEK). If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. It is recommended to use VM disks encrypted with CSEK for business-critical VM instances.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST CSF', 'NIST 800', 'PCI-DSS']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
