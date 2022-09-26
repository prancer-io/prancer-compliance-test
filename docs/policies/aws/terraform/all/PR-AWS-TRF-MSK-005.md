



# Title: Ensure Amazon MSK cluster has logging enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MSK-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MSK-005|
|eval|data.rule.msk_cluster_logging_enable|
|message|data.rule.msk_cluster_logging_enable_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MSK_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Consistent cluster logging helps you determine if a request was made with root or AWS Identity and Access Management (IAM) user credentials and whether the request was made with temporary security credentials for a role or federated user.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_msk_cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/msk.rego
