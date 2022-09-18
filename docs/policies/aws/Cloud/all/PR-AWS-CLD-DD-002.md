



# Title: Ensure DynamoDB PITR is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-DD-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_DD']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DD-002|
|eval|data.rule.dynamodb_PITR_enable|
|message|data.rule.dynamodb_PITR_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DD_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800']|
|service|['dynamodb']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
