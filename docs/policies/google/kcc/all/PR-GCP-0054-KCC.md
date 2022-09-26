



# Title: Service Account Key Not Rotated


***<font color="white">Master Test Id:</font>*** TEST_IAMServiceAccountKey

***<font color="white">Master Snapshot Id:</font>*** ['KCC_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([IAMServiceAccountKey.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0054-KCC|
|eval|data.rule.service_account_key_not_rotated|
|message|data.rule.service_account_key_not_rotated_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** A service account key hasn't been rotated for more than 90 days  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['kcc']|


***<font color="white">Resource Types:</font>*** ['iamserviceaccountkey']


[IAMServiceAccountKey.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMServiceAccountKey.rego
