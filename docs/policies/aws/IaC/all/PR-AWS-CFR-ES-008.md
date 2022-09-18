



# Title: AWS Elasticsearch domain is not configured with HTTPS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ES-008

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ES-008|
|eval|data.rule.esearch_enforce_https|
|message|data.rule.esearch_enforce_https_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-enforcehttps' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ES_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Elasticsearch domains that are not configured with HTTPS. Amazon Elasticsearch domains allow all traffic to be submitted over HTTPS, ensuring all communications between application and domain are encrypted. It is recommended to enable HTTPS so that all communication between the application and all data access goes across an encrypted communication channel to eliminate man-in-the-middle attacks  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Data protection', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-16.1', 'New Zealand Information Security Manual (NZISM v3.4)-22.1']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticsearch::domain']


[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elasticsearch.rego
