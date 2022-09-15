



# Master Test ID: PR-AWS-CLD-DD-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_DD']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DD-003|
|eval|data.rule.dynamodb_kinesis_stream|
|message|data.rule.dynamodb_kinesis_stream_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-kinesisstreamspecification.html#cfn-dynamodb-kinesisstreamspecification-streamarn' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DD_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** dynamodb kinesis specification property should not be null

***<font color="white">Description:</font>*** dynamodb kinesis specification property should not be null  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['dynamodb']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
