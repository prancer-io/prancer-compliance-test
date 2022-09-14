



# Master Test ID: PR-AWS-CLD-DAX-003


Master Snapshot Id: ['TEST_DAX', 'TEST_KMS']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DAX-003|
|eval: |data.rule.dax_gs_managed_key|
|message: |data.rule.dax_gs_managed_key_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dax.html#DAX.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DAX_003.py|


severity: Medium

title: Ensure for AWS DAX GS-managed key is used in encryption.

description: It is to check that data at rest encryption has used firm managed CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service: |['dax', 'kms']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
