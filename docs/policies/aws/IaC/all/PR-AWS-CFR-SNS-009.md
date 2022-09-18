



# Title: Ensure SNS is only accessible via specific VPCe service.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SNS-009

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SNS-009|
|eval|data.rule.sns_accessible_via_specific_vpc|
|message|data.rule.sns_accessible_via_specific_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SNS_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if SNS to other AWS services communication is over the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['MAS TRM', 'RMiT']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sns::topicpolicy']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego
