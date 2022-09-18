



# Title: Ensure AWS DocumentDB logging is enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DDB-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DDB-002|
|eval|data.rule.docdb_cluster_logs|
|message|data.rule.docdb_cluster_logs_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DDB_002.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::docdb::dbcluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
