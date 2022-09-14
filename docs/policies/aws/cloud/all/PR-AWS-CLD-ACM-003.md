



# Master Test ID: PR-AWS-CLD-ACM-003


Master Snapshot Id: ['TEST_ACM']

type: rego

rule: [file(acm.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ACM-003|
|eval: |data.rule.acm_certificate_arn|
|message: |data.rule.acm_certificate_arn_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ACM_003.py|


severity: Medium

title: Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities

description: Ensure that the aws certificate manager/ACMPCA Certificate CertificateAuthorityArn property references (using Fn::GetAtt or Ref) a Private CA, or that the property is not used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['acm']|



[file(acm.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/acm.rego
