



# Title: Ensure ElasticSearch has a custom endpoint configured.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ES-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ES-010|
|eval|data.rule.esearch_custom_endpoint_configured|
|message|data.rule.esearch_custom_endpoint_configured_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ES_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if a default endpoint is configured for ES domain.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CSA CCM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_elasticsearch_domain']


[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elasticsearch.rego
