



# Title: Ensure ACM Certification Validation Method set to DNS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ACM-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([acm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ACM-004|
|eval|data.rule.acm_certificate_validation|
|message|data.rule.acm_certificate_validation_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ACM_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that the AWS::ACM::Certificate ValidationMethod is set to DNS. This will restrict the developers ability to use email for domain validation.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::certificatemanager::certificate']


[acm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/acm.rego
