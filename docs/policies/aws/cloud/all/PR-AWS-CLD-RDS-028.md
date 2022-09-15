



# Master Test ID: PR-AWS-CLD-RDS-028


***<font color="white">Master Snapshot Id:</font>*** ['TEST_RDS_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-RDS-028|
|eval|data.rule.rds_cluster_backup_retention|
|message|data.rule.rds_cluster_backup_retention_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_RDS_028.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure AWS RDS Cluster has setup backup retention period of at least 30 days

***<font color="white">Description:</font>*** This policy checks that backup retention period for RDS DB is firm approved.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR', 'CIS', 'HITRUST', 'NIST 800', 'HIPAA', 'ISO 27001', 'SOC 2']|
|service|['rds']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
