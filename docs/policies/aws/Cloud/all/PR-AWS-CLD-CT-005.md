



# Title: Ensure AWS CloudTrail is logging data events for S3 and Lambda.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-CT-005

***<font color="white">Master Snapshot Id:</font>*** ['TEST_CT_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([cloudtrail.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-CT-005|
|eval|data.rule.logging_data_events_for_s3_and_lambda|
|message|data.rule.logging_data_events_for_s3_and_lambda_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.get_event_selectors' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_CT_005.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks that CloudTrail data event is enabled for S3 and Lambda.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CIS', 'PCI DSS', 'NIST 800', 'GDPR']|
|service|['cloudtrail']|



[cloudtrail.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/cloudtrail.rego
