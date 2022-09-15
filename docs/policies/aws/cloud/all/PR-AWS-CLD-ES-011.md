



# Master Test ID: PR-AWS-CLD-ES-011


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-011|
|eval|data.rule.esearch_slow_logs_is_enabled|
|message|data.rule.esearch_slow_logs_is_enabled_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_011.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure Slow Logs feature is enabled for ElasticSearch cluster.

***<font color="white">Description:</font>*** It checks of slow logs is enabled for the ES cluster. Slow logs provide valuable information for optimizing and troubleshooting your search and indexing operations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR', 'CSA CCM']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
