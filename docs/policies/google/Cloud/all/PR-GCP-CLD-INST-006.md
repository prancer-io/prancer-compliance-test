



# Title: VM Instances without any Label information


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-INST-006

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_INSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-INST-006|
|eval|data.rule.vm_no_labels|
|message|data.rule.vm_no_labels_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_INST_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** VM instance does not have any Labels. Labels can be used for easy identification and searches.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
