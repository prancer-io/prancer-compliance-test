



# Master Test ID: PR-AWS-CLD-DAX-001


Master Snapshot Id: ['TEST_DAX']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DAX-001|
|eval: |data.rule.dax_encrypt|
|message: |data.rule.dax_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DAX_001.py|


severity: Medium

title: Ensure DAX is securely encrypted at rest

description: Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service: |['dax']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
