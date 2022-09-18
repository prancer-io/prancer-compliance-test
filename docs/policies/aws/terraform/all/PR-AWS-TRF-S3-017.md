



# Title: Ensure S3 bucket cross-region replication is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-S3-017

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-S3-017|
|eval|data.rule.s3_cross_region_replica|
|message|data.rule.s3_cross_region_replica_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_S3_017.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_s3_bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
