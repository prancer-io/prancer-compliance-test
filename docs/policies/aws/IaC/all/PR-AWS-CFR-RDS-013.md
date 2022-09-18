



# Title: Ensure RDS clusters and instances have deletion protection enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-RDS-013

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-RDS-013|
|eval|data.rule.rds_cluster_deletion_protection|
|message|data.rule.rds_cluster_deletion_protection_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_RDS_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::rds::dbcluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
