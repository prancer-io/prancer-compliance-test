



# Master Test ID: PR-AWS-CLD-ES-002


Master Snapshot Id: ['TEST_ELASTICSEARCH']

type: rego

rule: [file(elasticsearch.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ES-002|
|eval: |data.rule.esearch_encrypt|
|message: |data.rule.esearch_encrypt_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ES_002.py|


severity: Low

title: AWS Elasticsearch domain Encryption for data at rest is disabled

description: This policy identifies Elasticsearch domains for which encryption is disabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your Elasticsearch domains components. This may include all data of file systems, primary and replica indices, log files, memory swap files and automated snapshots. The Elasticsearch uses AWS KMS service to store and manage the encryption keys. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 34', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-EKM-03', 'CSA CCM v3.0.1-MOS-11', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.177', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.191', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:06.d', 'HITRUST CSF v9.3-Control Reference:09.l', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO 27001', 'ISO 27001:2013-A.18.1.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-11.1.3', 'MLPS', 'MLPS 2.0-8.1.4.8', 'NIST 800', 'NIST 800-171 Rev1-3.13.16', 'NIST 800-53 Rev 5-Protection of Information at Rest', 'NIST 800-53 Rev4-SC-28', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.51', 'Risk Management in Technology (RMiT)-10.68', 'Risk Management in Technology (RMiT)-11.15']|
|service: |['elasticsearch']|



[file(elasticsearch.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
