



# Master Test ID: PR-AWS-CLD-SNS-009


Master Snapshot Id: ['TEST_SNS_02']

type: rego

rule: [file(sns.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SNS-009|
|eval: |data.rule.sns_accessible_via_specific_vpc|
|message: |data.rule.sns_accessible_via_specific_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SNS_009.py|


severity: Low

title: Ensure SNS is only accessible via specific VPCe service.

description: It checks if SNS to other AWS services communication is over the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['MAS TRM', 'RMiT']|
|service: |['sns']|



[file(sns.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
