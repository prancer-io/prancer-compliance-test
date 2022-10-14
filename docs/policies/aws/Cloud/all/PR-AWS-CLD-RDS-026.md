



# Title: Ensure AWS RDS Snapshot with access for only monitored cloud accounts.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-RDS-026

***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_06']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-026|
|eval|data.rule.rds_snapshot_with_access|
|message|data.rule.rds_snapshot_with_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_snapshot_attributes' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_026.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies RDS snapshots with access for unmonitored cloud accounts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
