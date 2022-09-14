



# Master Test ID: PR-AWS-CLD-DDB-002


Master Snapshot Id: ['TEST_DDB_01']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-DDB-002|
|eval: |data.rule.docdb_cluster_logs|
|message: |data.rule.docdb_cluster_logs_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_DDB_002.py|


severity: Low

title: Ensure AWS DocumentDB logging is enabled

description: The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['docdb']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
