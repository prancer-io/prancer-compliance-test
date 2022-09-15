



# Master Test ID: PR-AWS-CLD-ES-016


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-016|
|eval|data.rule.elasticsearch_gs_managed_key|
|message|data.rule.elasticsearch_gs_managed_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_016.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure ElasticSearch is encrypted at rest with GS managed KMS.

***<font color="white">Description:</font>*** It checks if the encryption at rest is enabled using a GS managed KMS CMK.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CCPA', 'CMMC', 'HITRUST', 'LGPD', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST SP', 'PCI-DSS', 'PIPEDA', 'RMiT']|
|service|['elasticsearch', 'kms']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
