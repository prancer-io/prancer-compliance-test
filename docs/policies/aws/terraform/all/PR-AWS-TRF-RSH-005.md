



# Title: Ensure Redshift cluster allow version upgrade by default


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-005|
|eval|data.rule.redshift_allow_version_upgrade|
|message|data.rule.redshift_allow_version_upgrade_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
