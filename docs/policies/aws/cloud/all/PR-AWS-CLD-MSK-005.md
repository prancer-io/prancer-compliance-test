



# Master Test ID: PR-AWS-CLD-MSK-005


Master Snapshot Id: ['TEST_MSK']

type: rego

rule: [file(msk.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-MSK-005|
|eval: |data.rule.msk_cluster_logging_enable|
|message: |data.rule.msk_cluster_logging_enable_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-cloudwatchlogs' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_MSK_005.py|


severity: Medium

title: Ensure Amazon MSK cluster has logging enabled

description: Consistent cluster logging helps you determine if a request was made with root or AWS Identity and Access Management (IAM) user credentials and whether the request was made with temporary security credentials for a role or federated user.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['msk']|



[file(msk.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
