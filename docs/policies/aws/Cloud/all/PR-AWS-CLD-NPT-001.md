



# Title: Ensure Neptune logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-NPT-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_NPT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-NPT-001|
|eval|data.rule.neptune_cluster_logs|
|message|data.rule.neptune_cluster_logs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html#cfn-neptune-dbcluster-enablecloudwatchlogsexports' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_NPT_001.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** These access logs can be used to analyze traffic patterns and troubleshoot security and operational issues.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['neptune']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
