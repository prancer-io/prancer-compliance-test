



# Title: Ensure custom endpoint has GS-managed ACM certificate associated in ElasticSearch.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ES-014

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-014|
|eval|data.rule.custom_endpoint_has_certificate|
|message|data.rule.custom_endpoint_has_certificate_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks the custom endpoint is hooked to a SSL certificate from AWS ACM.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
