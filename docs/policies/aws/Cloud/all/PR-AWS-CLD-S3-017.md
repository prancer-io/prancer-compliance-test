



# Title: Ensure S3 bucket cross-region replication is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-S3-017

***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-017|
|eval|data.rule.s3_cross_region_replica|
|message|data.rule.s3_cross_region_replica_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_017.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
