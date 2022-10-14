



# Title: Ensure enhanaced monitoring for AWS MSK is not set to default.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-MSK-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-MSK-006|
|eval|data.rule.msk_cluster_enhanced_monitoring_enable|
|message|data.rule.msk_cluster_enhanced_monitoring_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#aws-resource-msk-cluster--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_MSK_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is used to check that enhanced monitoring is configured to gather Apache Kafka metrics and sends them to Amazon CloudWatch.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::msk::cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/msk.rego
