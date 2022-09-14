



# Master Test ID: PR-AWS-CLD-ES-013


Master Snapshot Id: ['TEST_ELASTICSEARCH']

type: rego

rule: [file(elasticsearch.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ES-013|
|eval: |data.rule.fine_grained_encryption_for_elasticsearch|
|message: |data.rule.fine_grained_encryption_for_elasticsearch_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ES_013.py|


severity: Medium

title: Ensure fine-grained access control is enabled during domain creation in ElasticSearch.

description: It checks if fine grained access controls is enabled for the ElasticSearch cluster and node to node encryption is enabled with it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR', 'CSA CCM']|
|service: |['elasticsearch']|



[file(elasticsearch.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
