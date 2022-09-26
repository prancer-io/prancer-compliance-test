



# Title: AWS RDS instance with copy tags to snapshots disabled


***<font color="white">Master Test Id:</font>*** TEST_RDS_4

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([rds.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0128-ACK|
|eval|data.rule.rds_snapshot|
|message|data.rule.rds_snapshot_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[rds.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/rds.rego
