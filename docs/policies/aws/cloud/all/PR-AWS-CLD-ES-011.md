



# Master Test ID: PR-AWS-CLD-ES-011


Master Snapshot Id: ['TEST_ELASTICSEARCH']

type: rego

rule: [file(elasticsearch.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ES-011|
|eval: |data.rule.esearch_slow_logs_is_enabled|
|message: |data.rule.esearch_slow_logs_is_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ES_011.py|


severity: Low

title: Ensure Slow Logs feature is enabled for ElasticSearch cluster.

description: It checks of slow logs is enabled for the ES cluster. Slow logs provide valuable information for optimizing and troubleshooting your search and indexing operations.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR', 'CSA CCM']|
|service: |['elasticsearch']|



[file(elasticsearch.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
