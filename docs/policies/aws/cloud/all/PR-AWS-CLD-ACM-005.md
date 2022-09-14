



# Master Test ID: PR-AWS-CLD-ACM-005


Master Snapshot Id: ['TEST_ACM']

type: rego

rule: [file(acm.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ACM-005|
|eval: |data.rule.acm_do_not_have_unused_certificate|
|message: |data.rule.acm_do_not_have_unused_certificate_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ACM_005.py|


severity: Low

title: Ensure Certificate Manager (ACM) does not have unused certificates.

description: It checkes if the ACM certificates provisioned are not left unused in ACM.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA CCM', 'HITRUST', 'NIST 800']|
|service: |['acm']|



[file(acm.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/acm.rego
