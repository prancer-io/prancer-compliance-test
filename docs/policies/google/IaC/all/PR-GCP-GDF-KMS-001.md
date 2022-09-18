



# Title: Ensure GCP KMS encryption key rotating in every 90 days


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-KMS-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([kms.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-KMS-001|
|eval|data.rule.kms_key_rotation|
|message|data.rule.kms_key_rotation_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_KMS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP KMS encryption keys that are not rotating every 90 days.  A key is used to protect some corpus of data. A collection of files could be encrypted with the same key and people with decrypt permissions on that key would be able to decrypt those files. It's recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old key.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['gcp-types/cloudkms-v1:projects.locations.keyrings.cryptokeys']


[kms.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/kms.rego
