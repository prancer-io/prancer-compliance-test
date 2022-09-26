



# Title: VM Instances enabled with Pre-Emptible termination


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-INST-004

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_INSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-INST-004|
|eval|data.rule.vm_pre_emptible|
|message|data.rule.vm_pre_emptible_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_INST_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to verify if any VM instance is initiated with the flag 'Pre-Emptible termination' set to True. Setting this instance to True implies that this VM instance will shut down within 24 hours or can also be terminated by a Service Engine when high demand is encountered. While this might save costs, it can also lead to unexpected loss of service when the VM instance is terminated.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM']|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
