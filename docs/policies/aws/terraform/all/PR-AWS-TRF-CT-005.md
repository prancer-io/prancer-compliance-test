



# Title: Ensure AWS CloudTrail is logging data events for S3 and Lambda.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-CT-005

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-CT-005|
|eval|data.rule.logging_data_events_for_s3_and_lambda|
|message|data.rule.logging_data_events_for_s3_and_lambda_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_CT_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks that CloudTrail data event is enabled for S3 and Lambda.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'PCI-DSS', 'NIST 800', 'GDPR']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_cloudtrail']


[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/cloudtrail.rego
