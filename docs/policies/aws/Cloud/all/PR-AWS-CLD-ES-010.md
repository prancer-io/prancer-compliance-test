



# Title: Ensure ElasticSearch has a custom endpoint configured.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ES-010

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-010|
|eval|data.rule.esearch_custom_endpoint_configured|
|message|data.rule.esearch_custom_endpoint_configured_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if a default endpoint is configured for ES domain.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR', 'CSA CCM']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
