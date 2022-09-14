



# Master Test ID: PR-AZR-TRF-SQL-051


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(dbvulnerabilityassessments.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-SQL-051|
|eval: |data.rule.mssql_ads_scan_configured|
|message: |data.rule.mssql_ads_scan_configured_err|
|remediationDescription: |In 'azurerm_mssql_server_vulnerability_assessment' resource, make sure 'storage_container_path' exist to fix the issue. please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_vulnerability_assessment#storage_container_path' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_SQL_051.py|


severity: Low

title: Azure SQL Server advanced data security should be enabled

description: Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that do not have ADS enabled. As a best practice, enable ADS on mission-critical SQL servers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-3', 'Azure Security Benchmark (v3)-DS-6', 'Azure Security Benchmark (v3)-PV-5', 'CIS', 'CIS v1.2.0 (Azure)-4.2.5', 'CIS v1.3.0 (Azure)-4.2.2', 'CIS v1.3.1 (Azure)-4.2.2', 'CIS v1.4.0 (Azure)-4.2.2', 'CSA CCM', 'CSA CCM v.4.0.1-A&A-03', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-DSP-01', 'CSA CCM v.4.0.1-DSP-04', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-TVM-01', 'CSA CCM v.4.0.1-TVM-07', 'CSA CCM v.4.0.1-TVM-08', 'CSA CCM v.4.0.1-TVM-09', 'CSA CCM v.4.0.1-TVM-10', 'CSA CCM v.4.0.1-UEM-03', 'CSA CCM v.4.0.1-UEM-06', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.m', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.1', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-12.6.1', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27002:2013-14.2.4', 'ISO/IEC 27002:2013-16.1.2', 'ISO/IEC 27002:2013-16.1.3', 'ISO/IEC 27002:2013-18.2.1', 'ISO/IEC 27002:2013-5.1.1', 'ISO/IEC 27002:2013-5.1.2', 'ISO/IEC 27002:2013-8.2.1', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'ISO/IEC 27018:2019-18.2.1', 'NIST CSF', 'NIST CSF-DE.AE-4', 'NIST CSF-DE.CM-8', 'NIST CSF-ID.RA-1', 'NIST CSF-ID.RA-3', 'NIST CSF-ID.RA-4', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.IP-1', 'NIST CSF-RS.AN-2', 'NIST CSF-RS.MI-3', 'NIST SP', 'NIST SP 800-171 Revision 2-3.11.1', 'NIST SP 800-171 Revision 2-3.11.2', 'NIST SP 800-172-3.12.1e', 'PCI DSS', 'PCI DSS v3.2.1-6.1', 'PCI DSS v3.2.1-6.2']|
|service: |['terraform']|


resourceTypes: ['azurerm_mssql_server', 'azurerm_mssql_server_vulnerability_assessment']


[file(dbvulnerabilityassessments.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/dbvulnerabilityassessments.rego
