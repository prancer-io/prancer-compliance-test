



# Master Test ID: PR-AWS-CLD-RDS-013


Master Snapshot Id: ['TEST_RDS_02']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-013|
|eval: |data.rule.rds_cluster_deletion_protection|
|message: |data.rule.rds_cluster_deletion_protection_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_013.py|


severity: Low

title: Ensure RDS clusters and instances have deletion protection enabled

description: This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1485 - Data Destruction', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-22.1']|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
