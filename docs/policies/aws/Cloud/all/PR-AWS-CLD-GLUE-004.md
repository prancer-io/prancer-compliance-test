



# Title: Ensure AWS Glue encrypt data at rest with GS managed Customer Master Key (CMK).


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-GLUE-004

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_06', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-GLUE-004|
|eval|data.rule.glue_cmk_key|
|message|data.rule.glue_cmk_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/glue.html#Glue.Client.get_security_configuration' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_GLUE_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It is to check that GS managed CMK is used for AWS Glue encryption at rest.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['glue']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
