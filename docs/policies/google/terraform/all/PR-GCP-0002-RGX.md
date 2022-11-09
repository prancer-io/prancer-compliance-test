



# Title: There is a possibility that secure password is exposed


***<font color="white">Master Test Id:</font>*** PR-GCP-0002-RGX

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_tf.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-0002-RGX|
|eval|entropy_password|
|message|entropy_password_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** There is a possibility that secure password is exposed  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|



[secret_tf.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/secret_tf.py
