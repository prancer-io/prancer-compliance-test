



# Title: Ensure 'default' value is not used on Security Group setting for Redis cache engines


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC-006|
|eval|data.rule.cache_default_sg|
|message|data.rule.cache_default_sg_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure 'default' value is not used on Security Group setting for Redis cache engines  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_elasticache_replication_group']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
