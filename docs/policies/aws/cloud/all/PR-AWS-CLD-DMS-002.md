



# Master Test ID: PR-AWS-CLD-DMS-002


Master Snapshot Id: ['TEST_DMS_02']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DMS-002|
|eval: |data.rule.dms_public_access|
|message: |data.rule.dms_public_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DMS_002.py|


severity: High

title: Ensure DMS replication instance is not publicly accessible

description: Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service: |['dms']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
