



# Master Test ID: PR-AWS-CLD-SNS-010


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SNS_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SNS-010|
|eval|data.rule.sns_secure_data_transport|
|message|data.rule.sns_secure_data_transport_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SNS_010.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure SNS topic is configured with secure data transport policy.

***<font color="white">Description:</font>*** It check if the SNs topics are configured with secure data transport policy via SSL.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['MAS TRM', 'RMiT']|
|service|['sns']|



[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sns.rego
