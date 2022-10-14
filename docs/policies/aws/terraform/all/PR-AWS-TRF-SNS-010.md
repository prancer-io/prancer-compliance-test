



# Title: Ensure SNS topic is configured with secure data transport policy.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SNS-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SNS-010|
|eval|data.rule.sns_secure_data_transport|
|message|data.rule.sns_secure_data_transport_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SNS_010.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It check if the SNs topics are configured with secure data transport policy via SSL.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM', 'RMiT']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_sns_topic_policy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego
