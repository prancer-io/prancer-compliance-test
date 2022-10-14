



# Title: Ensure authentication to Kibana is SAML based in ElasticSearch.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ES-012

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-012|
|eval|data.rule.authentication_is_saml_based|
|message|data.rule.authentication_is_saml_based_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_012.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if basic authentication is used to login to Kibana dashboard.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
