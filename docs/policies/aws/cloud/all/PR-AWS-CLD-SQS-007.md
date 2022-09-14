



# Master Test ID: PR-AWS-CLD-SQS-007


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-007|
|eval: |data.rule.sqs_accessible_via_specific_vpc|
|message: |data.rule.sqs_accessible_via_specific_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_007.py|


severity: Low

title: Ensure SQS is only accessible via specific VPCe service.

description: It checks if SQS to other AWS services communication is managed by VPC endpoint and polcicies attached to it  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA CCM', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'RMiT']|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
