



# Master Test ID: PR-AWS-CLD-ES-010


Master Snapshot Id: ['TEST_ELASTICSEARCH']

type: rego

rule: [file(elasticsearch.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ES-010|
|eval: |data.rule.esearch_custom_endpoint_configured|
|message: |data.rule.esearch_custom_endpoint_configured_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ES_010.py|


severity: Medium

title: Ensure ElasticSearch has a custom endpoint configured.

description: It checks if a default endpoint is configured for ES domain.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['NIST 800', 'GDPR', 'CSA CCM']|
|service: |['elasticsearch']|



[file(elasticsearch.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
