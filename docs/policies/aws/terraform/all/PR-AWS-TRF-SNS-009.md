



# Title: Ensure SNS is only accessible via specific VPCe service.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SNS-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SNS-009|
|eval|data.rule.sns_accessible_via_specific_vpc|
|message|data.rule.sns_accessible_via_specific_vpc_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SNS_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if SNS to other AWS services communication is over the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sns_topic_policy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego
