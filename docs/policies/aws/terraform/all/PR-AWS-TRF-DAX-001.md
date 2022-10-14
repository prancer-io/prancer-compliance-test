



# Title: Ensure DAX is securely encrypted at rest


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DAX-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DAX-001|
|eval|data.rule.dax_encrypt|
|message|data.rule.dax_encrypt_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DAX_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_dax_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
