



# Title: There is a possibility that Aws access key id is exposed


***<font color="white">Master Test Id:</font>*** PR-AWS-0030-RGX

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** python

***<font color="white">rule:</font>*** file([secret_tf.py])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0030-RGX|
|eval|al_access_key_id|
|message|al_access_key_id_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** []


[secret_tf.py]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/secret_tf.py
