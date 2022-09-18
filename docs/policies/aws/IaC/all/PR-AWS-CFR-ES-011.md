



# Title: Ensure Slow Logs feature is enabled for ElasticSearch cluster.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ES-011

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ES-011|
|eval|data.rule.esearch_slow_logs_is_enabled|
|message|data.rule.esearch_slow_logs_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ES_011.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks of slow logs is enabled for the ES cluster. Slow logs provide valuable information for optimizing and troubleshooting your search and indexing operations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CSA CCM']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticsearch::domain']


[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elasticsearch.rego
