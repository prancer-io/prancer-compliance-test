



# Title: Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-025

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-025|
|eval|data.rule.sqs_queue_is_publicly_accessible_through_iam_policies|
|message|data.rule.sqs_queue_is_publicly_accessible_through_iam_policies_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_025.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies the AWS SQS Queue resources which are publicly accessible through IAM policies. Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_role']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
