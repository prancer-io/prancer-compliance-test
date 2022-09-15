



# Master Test ID: PR-AWS-CLD-SNS-009


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SNS_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SNS-009|
|eval|data.rule.sns_accessible_via_specific_vpc|
|message|data.rule.sns_accessible_via_specific_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SNS_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure SNS is only accessible via specific VPCe service.

***<font color="white">Description:</font>*** It checks if SNS to other AWS services communication is over the internet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['MAS TRM', 'RMiT']|
|service|['sns']|



[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
