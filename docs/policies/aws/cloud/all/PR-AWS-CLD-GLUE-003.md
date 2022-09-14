



# Master Test ID: PR-AWS-CLD-GLUE-003


Master Snapshot Id: ['TEST_ALL_06']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-GLUE-003|
|eval: |data.rule.glue_encrypt_data_at_rest|
|message: |data.rule.glue_encrypt_data_at_rest_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/glue.html#Glue.Client.get_security_configuration' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_GLUE_003.py|


severity: High

title: Ensure AWS Glue encrypt data at rest.

description: It is to check that AWS Glue encryption at rest is enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'NIST 800']|
|service: |['glue']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
