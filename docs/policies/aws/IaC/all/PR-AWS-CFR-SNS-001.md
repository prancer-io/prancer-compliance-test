



# Title: AWS SNS subscription is not configured with HTTPS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SNS-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SNS-001|
|eval|data.rule.sns_protocol|
|message|data.rule.sns_protocol_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SNS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sns::subscription']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego
