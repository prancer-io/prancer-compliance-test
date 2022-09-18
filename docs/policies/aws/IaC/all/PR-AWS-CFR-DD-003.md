



# Title: Dynamo DB kinesis specification property should not be null


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DD-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DD-003|
|eval|data.rule.dynamodb_kinesis_stream|
|message|data.rule.dynamodb_kinesis_stream_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-kinesisstreamspecification.html#cfn-dynamodb-kinesisstreamspecification-streamarn' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DD_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Dynamo DB kinesis specification property should not be null  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::dynamodb::table']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
