



# Title: Ensure EMR cluster is not visible to all IAM users.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EMR-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([emr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EMR-009|
|eval|data.rule.emr_cluster_not_visible_to_all_iam_users|
|message|data.rule.emr_cluster_not_visible_to_all_iam_users_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EMR_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the EMR cluster created has a wide visibility to all IAM users. When true, IAM principals in the AWS account can perform EMR cluster actions that their IAM policies allow.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_emr_cluster']


[emr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/emr.rego
