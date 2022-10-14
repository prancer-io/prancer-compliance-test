



# Title: Ensure CloudWatch Alarm Metrics AccountId is valid


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-CW-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-CW-001|
|eval|data.rule.cw_alarm_account_id|
|message|data.rule.cw_alarm_account_id_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudwatch-alarm-metricdataquery.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_CW_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure CloudWatch Alarm Metrics AccountId is valid  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudwatch']|


***<font color="white">Resource Types:</font>*** ['aws::cloudwatch::alarm']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
