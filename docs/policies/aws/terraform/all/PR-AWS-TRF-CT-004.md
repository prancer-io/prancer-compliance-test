



# Title: CloudTrail trail is not integrated with CloudWatch Log


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CT-004

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CT-004|
|eval|data.rule.ct_cloudwatch|
|message|data.rule.ct_cloudwatch_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CT_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudtrail']


[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/cloudtrail.rego
