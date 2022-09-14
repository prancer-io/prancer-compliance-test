



# Master Test ID: PR-AWS-CLD-ES-014


Master Snapshot Id: ['TEST_ELASTICSEARCH']

type: rego

rule: [file(elasticsearch.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ES-014|
|eval: |data.rule.custom_endpoint_has_certificate|
|message: |data.rule.custom_endpoint_has_certificate_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ES_014.py|


severity: Medium

title: Ensure custom endpoint has GS-managed ACM certificate associated in ElasticSearch.

description: It checks the custom endpoint is hooked to a SSL certificate from AWS ACM.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['elasticsearch']|



[file(elasticsearch.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
