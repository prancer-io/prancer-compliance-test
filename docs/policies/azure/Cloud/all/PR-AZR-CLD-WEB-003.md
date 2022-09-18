



# Title: Web App should have incoming client certificates enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-WEB-003

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_100']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([web.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-WEB-003|
|eval|data.rule.client_cert_enabled|
|message|data.rule.client_cert_enabled_err|
|remediationDescription|1. Go to 'App Services' from Azure Management console and choose your App Service.<br>2. Under 'Settings, select 'Configuration' on the navigation menu.<br>3. Select 'General Settings'.<br>4. Go to 'Client Certificate mode' under 'Incoming Client Certificates' and select 'Require' Button.<br>5. Click Save.<br><br>Note: By default, Client Certificate mode is set to Ignore.<br><br>References:<a href='https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth' target='_blank'>https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth</a>|
|remediationFunction|PR_AZR_CLD_WEB_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Client certificates allow the Web App to require a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-4', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS v1.1 (Azure)-9.4', 'CIS v1.2.0 (Azure)-9.4', 'CIS v1.3.0 (Azure)-9.4', 'CIS v1.3.1 (Azure)-9.4', 'CIS v1.4.0 (Azure)-9.4', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.013', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'NIST 800', 'NIST 800-53 Rev 5-Signed Components', 'NIST 800-53 Rev4-CM-5 (3)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.5.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service|['Compute']|



[web.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/web.rego
