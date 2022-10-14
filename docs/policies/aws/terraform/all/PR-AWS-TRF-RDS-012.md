



# Title: AWS RDS cluster retention policy less than 7 days


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RDS-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RDS-012|
|eval|data.rule.rds_cluster_retention|
|message|data.rule.rds_cluster_retention_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RDS_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** RDS cluster Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_rds_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
