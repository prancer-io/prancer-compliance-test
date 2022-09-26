



# Title: Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ACM-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ACM']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([acm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ACM-003|
|eval|data.rule.acm_certificate_arn|
|message|data.rule.acm_certificate_arn_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ACM_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that the aws certificate manager/ACMPCA Certificate CertificateAuthorityArn property references (using Fn::GetAtt or Ref) a Private CA, or that the property is not used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['acm']|



[acm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/acm.rego
