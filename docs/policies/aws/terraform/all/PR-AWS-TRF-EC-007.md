



# Title: Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC-007

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC-007|
|eval|data.rule.automatic_backups_for_redis_cluster|
|message|data.rule.automatic_backups_for_redis_cluster_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if automatic backups are enabled for the Redis cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_elasticache_cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
