



# Master Test ID: PR-AWS-CLD-S3-017


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-017|
|eval: |data.rule.s3_cross_region_replica|
|message: |data.rule.s3_cross_region_replica_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_017.py|


severity: Medium

title: Ensure S3 bucket cross-region replication is enabled

description: Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
