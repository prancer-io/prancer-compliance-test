



# Title: Ensure GCP VM instance not using a default service account with full access to all Cloud APIs


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-INST-012

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-INST-012|
|eval|data.rule.compute_default_service_full_access|
|message|data.rule.compute_default_service_full_access_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_INST_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the GCP VM instances which are using a default service account with full access to all Cloud APIs. To compliant with the principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned to default service account 'Compute Engine default service account' with scope 'Allow full access to all Cloud APIs'.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.instance']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
