



# Master Test ID: PR-AWS-CLD-DD-004


Master Snapshot Id: ['TEST_DD', 'TEST_KMS']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DD-004|
|eval: |data.rule.dynamodb_not_customer_managed_key|
|message: |data.rule.dynamodb_not_customer_managed_key_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.describe_table' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DD_004.py|


severity: Medium

title: Ensure AWS DynamoDB does not uses customer managed CMK key to ensure encryption at rest.

description: It checks if the default AWS Key is used for encryption. GS mandates CMK to be used for encryption  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'CCPA', 'CMMC', 'CSA CCM', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'LGPD', 'MAS TRM', 'MLPS', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'PIPEDA', 'RMiT']|
|service: |['dynamodb', 'kms']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
