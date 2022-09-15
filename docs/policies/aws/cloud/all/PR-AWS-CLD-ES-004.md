



# Master Test ID: PR-AWS-CLD-ES-004


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-004|
|eval|data.rule.esearch_index_slow_log|
|message|data.rule.esearch_index_slow_log_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** AWS Elasticsearch domain has Index slow logs set to disabled

***<font color="white">Description:</font>*** This policy identifies Elasticsearch domains for which Index slow logs is disabled in your AWS account. Enabling support for publishing indexing slow logs to AWS CloudWatch Logs enables you have full insight into the performance of indexing operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific queries or due to changes in cluster usage, so that you can optimize your index configuration to address the problem.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', 'CSA CCM v3.0.1-DSI-06', 'CSA CCM v3.0.1-IAM-01', 'CSA CCM v3.0.1-IAM-02', 'CSA CCM v3.0.1-IAM-03', 'CSA CCM v3.0.1-IAM-04', 'CSA CCM v3.0.1-IAM-05', 'CSA CCM v3.0.1-IAM-09', 'CSA CCM v3.0.1-IAM-10', 'CSA CCM v3.0.1-IAM-11', 'CSA CCM v3.0.1-IAM-12', 'CSA CCM v3.0.1-IAM-13', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:09.aa', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.5.7', 'MLPS', 'MLPS 2.0-8.1.5.4', 'NIST 800', 'NIST 800-171 Rev1-3.1.1', 'NIST 800-171 Rev1-3.1.2', 'NIST 800-53 Rev 5-Account Management \| Automated Audit Actions', 'NIST 800-53 Rev4-AC-2 (4)', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.14.2e', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.61', 'Risk Management in Technology (RMiT)-10.66', 'SOC 2', 'SOC 2-CC6.2', 'SOC 2-CC6.3']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
