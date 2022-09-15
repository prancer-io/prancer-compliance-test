



# Master Test ID: PR-AWS-CLD-ES-009


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-009|
|eval|data.rule.esearch_encrypt_kms|
|message|data.rule.esearch_encrypt_kms_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_009.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Elasticsearch Domain should not have Encrytion using AWS Managed Keys

***<font color="white">Description:</font>*** Ensure that your Amazon ElasticSearch (ES) domains are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys (default keys used by the ES service when there are no customer keys defined) in order to have more granular control over the data-at-rest encryption/decryption process and to meet compliance requirements.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['NIST 800', 'GDPR']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
