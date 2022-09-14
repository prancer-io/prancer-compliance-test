



# Master Test ID: PR-AWS-CLD-RDS-015


Master Snapshot Id: ['TEST_RDS_04']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-015|
|eval: |data.rule.rds_global_cluster_encrypt|
|message: |data.rule.rds_global_cluster_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-globalcluster.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_015.py|


severity: Medium

title: AWS RDS Global DB cluster encryption is disabled

description: This policy identifies RDS Global DB clusters for which encryption is disabled. Amazon Aurora encrypted Global DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
