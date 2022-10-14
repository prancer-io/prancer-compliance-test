



# Title: Ensure RDS clusters and instances have deletion protection enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-013

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-013|
|eval|data.rule.rds_cluster_deletion_protection|
|message|data.rule.rds_cluster_deletion_protection_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_rds_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
