



# Master Test ID: PR-AZR-TRF-SQL-064


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(postgreSQL.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-064|
|eval: |data.rule.azurerm_postgresql_configuration_log_connections|
|message: |data.rule.azurerm_postgresql_configuration_log_connections_err|
|remediationDescription: |In 'azurerm_postgresql_configuration' resource, set name = 'log_connections' and value = 'on' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_064.py|


severity: Medium

title: PostgreSQL Database Server should have log_connections enabled

description: Causes each attempted connection to the server to be logged, as well as successful completion of client authentication. Only superusers can change this parameter at session start, and it cannot be changed at all within a session. this policy will identify Postgresql DB Server which dont have log_connections enabled and alert.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'APRA (CPS 234) Information Security-CPS234-35', 'APRA (CPS 234) Information Security-CPS234-36', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-LT-4', 'Azure Security Benchmark (v3)-DS-7', 'Brazilian Data Protection Law (LGPD)-Article 31', 'Brazilian Data Protection Law (LGPD)-Article 48', 'CIS', 'CIS v1.1 (Azure)-4.14', 'CIS v1.2.0 (Azure)-4.3.4', 'CIS v1.3.0 (Azure)-4.3.4', 'CIS v1.3.1 (Azure)-4.3.4', 'CIS v1.4.0 (Azure)-4.3.3', 'CSA CCM', 'CSA CCM v.4.0.1-LOG-05', 'CSA CCM v.4.0.1-LOG-06', 'CSA CCM v.4.0.1-LOG-08', 'CSA CCM v.4.0.1-LOG-13', "CyberSecurity Law of the People's Republic of China-Article 55", "CyberSecurity Law of the People's Republic of China-Article 56", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AU.3.046', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.ab', 'HITRUST v.9.4.2-Control Reference:09.ac', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.4.1', 'ISO/IEC 27002:2013-12.4.3', 'ISO/IEC 27002:2013-12.4.4', 'ISO/IEC 27002:2013-16.1.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.4.1', 'ISO/IEC 27017:2015-12.4.4', 'ISO/IEC 27017:2015-16.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Configuration Settings', 'NIST 800-53 Rev4-CM-6', 'NIST CSF', 'NIST CSF-PR.PT-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.3.4', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-10.2.3', 'PCI DSS v3.2.1-10.6']|
|service: |['terraform']|


resourceTypes: ['azurerm_postgresql_configuration', 'azurerm_postgresql_server', 'azurerm_postgresql_firewall_rule']


[file(postgreSQL.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego
