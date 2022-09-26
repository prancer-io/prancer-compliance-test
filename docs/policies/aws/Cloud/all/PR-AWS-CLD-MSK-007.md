



# Title: Ensure public access is disabled for AWS MSK.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-MSK-007

***<font color="white">Master Snapshot Id:</font>*** ['TEST_MSK']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MSK-007|
|eval|data.rule.msk_public_access|
|message|data.rule.msk_public_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MSK_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It check whether public access is turned on to the brokers of MSK clusters.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['msk']|



[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
