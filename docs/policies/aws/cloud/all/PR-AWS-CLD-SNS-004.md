



# Master Test ID: PR-AWS-CLD-SNS-004


Master Snapshot Id: ['TEST_SNS_02']

type: rego

rule: [file(sns.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SNS-004|
|eval: |data.rule.sns_policy_public|
|message: |data.rule.sns_policy_public_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SNS_004.py|


severity: Medium

title: Ensure SNS Topic policy is not publicly accessible

description: Public SNS Topic potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'GDPR']|
|service: |['sns']|



[file(sns.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
