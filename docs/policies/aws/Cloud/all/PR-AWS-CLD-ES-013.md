



# Title: Ensure fine-grained access control is enabled during domain creation in ElasticSearch.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-ES-013

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-013|
|eval|data.rule.fine_grained_encryption_for_elasticsearch|
|message|data.rule.fine_grained_encryption_for_elasticsearch_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_013.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if fine grained access controls is enabled for the ElasticSearch cluster and node to node encryption is enabled with it.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR', 'CSA CCM']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
