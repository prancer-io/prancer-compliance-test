



# Title: Ensure S3 Bucket NotificationConfiguration Property is not set.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-S3-022

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-S3-022|
|eval|data.rule.s3_notification_config|
|message|data.rule.s3_notification_config_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_S3_022.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Prevent S3 Bucket NotificationConfiguration from being set denying notifications from being sent to any SNS Topics, SQS Queues or Lambda functions.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::s3::bucket']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
