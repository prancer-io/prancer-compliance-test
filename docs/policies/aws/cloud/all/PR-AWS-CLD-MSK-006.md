



# Master Test ID: PR-AWS-CLD-MSK-006


***<font color="white">Master Snapshot Id:</font>*** ['TEST_MSK']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MSK-006|
|eval|data.rule.msk_cluster_enhanced_monitoring_enable|
|message|data.rule.msk_cluster_enhanced_monitoring_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MSK_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure enhanaced monitoring for AWS MSK is not set to default.

***<font color="white">Description:</font>*** It is used to check that enhanced monitoring is configured to gather Apache Kafka metrics and sends them to Amazon CloudWatch.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['msk']|



[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
