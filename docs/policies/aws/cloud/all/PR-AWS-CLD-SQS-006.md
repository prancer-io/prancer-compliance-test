



# Master Test ID: PR-AWS-CLD-SQS-006


Master Snapshot Id: ['TEST_SQS']

type: rego

rule: [file(sqs.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SQS-006|
|eval: |data.rule.sqs_not_overly_permissive|
|message: |data.rule.sqs_not_overly_permissive_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policydocument' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SQS_006.py|


severity: High

title: Ensure AWS SQS queue access policy is not overly permissive.

description: It identifies Simple Queue Service (SQS) queues that have an overly permissive access policy. It is highly recommended to have the least privileged access policy to protect the SQS queue from data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA CCM', 'CSA CCM v.4.0.1', 'HITRUST', 'HITRUST v.9.4.2', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'ISO/IEC 27002:2013', 'ISO/IEC 27017:2015', 'ISO/IEC 27018:2019', 'MAS TRM', 'MAS TRM 2021', 'NIST CSF', 'NIST SP', 'NIST SP 800-171 Revision 2', 'NIST SP 800-172', 'PCI-DSS', 'PCI DSS v3.2.1', 'RMiT', 'Risk Management in Technology (RMiT)']|
|service: |['sqs']|



[file(sqs.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sqs.rego
