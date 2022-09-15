



# Master Test ID: PR-AWS-CLD-DAX-002


***<font color="white">Master Snapshot Id:</font>*** ['TEST_DAX']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DAX-002|
|eval|data.rule.dax_cluster_endpoint_encrypt_at_rest|
|message|data.rule.dax_cluster_endpoint_encrypt_at_rest_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/dax/describe-clusters.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DAX_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure AWS DAX data is encrypted in transit

***<font color="white">Description:</font>*** This control is to check that the communication between the application and DAX is always encrypted  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['dax']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
