



# Title: VM instances without metadata, zone or label information


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-INST-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.instance.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-INST-007|
|eval|data.rule.vm_info|
|message|data.rule.vm_info_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_instance']


[compute.v1.instance.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.instance.rego
