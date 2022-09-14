



# Master Test ID: PR-AWS-CLD-RDS-026


Master Snapshot Id: ['TEST_RDS_06']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-026|
|eval: |data.rule.rds_snapshot_with_access|
|message: |data.rule.rds_snapshot_with_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_snapshot_attributes' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_026.py|


severity: Medium

title: Ensure AWS RDS Snapshot with access for only monitored cloud accounts.

description: It identifies RDS snapshots with access for unmonitored cloud accounts.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
