



# Master Test ID: PR-AWS-CLD-LG-002


Master Snapshot Id: ['TEST_ALL_03']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-LG-002|
|eval: |data.rule.log_group_retention|
|message: |data.rule.log_group_retention_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_LG_002.py|


severity: Medium

title: Ensure CloudWatch log groups has retention days defined

description: Ensure that your web-tier CloudWatch log group has the retention period feature configured in order to establish how long log events are kept in AWS CloudWatch Logs  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['cloudwatch']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
