



# Title: GCP User managed service account keys are not rotated for 90 days


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-SAK-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-SAK-001|
|eval|data.rule.svc_account_key|
|message|data.rule.svc_account_key_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_SAK_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['iam.v1.serviceaccounts.key']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/iam.rego
