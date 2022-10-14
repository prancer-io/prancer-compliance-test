



# Title: Ensure RDS instances uses AWS Secrets Manager for credentials.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RDS-020

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RDS-020|
|eval|data.rule.db_instance_secretmanager|
|message|data.rule.db_instance_secretmanager_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-monitoringinterval' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RDS_020.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** RDS instances must use AWS Secrets Manager for credentials. Passwords must be rotated every 90 days.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::rds::dbinstance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
