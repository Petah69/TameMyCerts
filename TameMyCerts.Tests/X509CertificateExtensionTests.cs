// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.X509;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class X509CertificateExtensionTests
    {
        [TestMethod]
        public void X509CertificateExtensionSecurityIdentifier_works()
        {
            const string expectedResult =
                "MD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMzgxMTg2MDUyLTQyNDc2OTIz" +
                "ODYtMTM1OTI4MDc4LTEyMjU=";

            const string sid = "S-1-5-21-1381186052-4247692386-135928078-1225";

            var sidExt = new X509CertificateExtensionSecurityIdentifier(new SecurityIdentifier(sid));

            Assert.IsTrue(Convert.ToBase64String(sidExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void X509CertificateExtensionOcspMustStaple_works()
        {
            const string expectedResult = "MAMCAQU=";

            var ocspStaplingExt = new X509CertificateExtensionOcspMustStaple();

            Assert.IsTrue(Convert.ToBase64String(ocspStaplingExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void X509CertificateExtensionCrlDistributionPoint_works()
        {
            const string expectedResult =
                "MIH/MIH8oIH5oIH2hoG6bGRhcDovLy9DTj1URVNULUNBLENOPVRFU1QtU0VSVkVS" +
                "LENOPUNEUCxDTj1QdWJsaWMgS2V5IFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv" +
                "bmZpZ3VyYXRpb24sREM9dGFtZW15Y2VydHMtdGVzdHMsREM9bG9jYWw/Y2VydGlm" +
                "aWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1" +
                "dGlvblBvaW50hjdodHRwOi8vcGtpLnRhbWVteWNlcnRzLXRlc3RzLmxvY2FsL0Nl" +
                "cnREYXRhL1RFU1QtQ0EuY3Js";
                
            var cdpExt = new X509CertificateExtensionCrlDistributionPoint();

            cdpExt.AddUri(
                "ldap:///CN=TEST-CA,CN=TEST-SERVER,CN=CDP,CN=Public Key Services," + 
                "CN=Services,CN=Configuration,DC=tamemycerts-tests,DC=local" +
                "?certificateRevocationList?base?objectClass=cRLDistributionPoint"
                );
            cdpExt.AddUri("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crl");

            cdpExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(cdpExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void X509CertificateExtensionAuthorityInformationAccess_works()
        {
            const string expectedResult =
                "MIIBLDCBrgYIKwYBBQUHMAKGgaFsZGFwOi8vL0NOPVRFU1QtQ0EsQ049QUlBLENO" +
                "PVB1YmxpYyBLZXkgU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv" +
                "bixEQz10YW1lbXljZXJ0cy10ZXN0cyxEQz1sb2NhbD9jQUNlcnRpZmljYXRlP2Jh" +
                "c2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBDBggrBgEFBQcw" +
                "AoY3aHR0cDovL3BraS50YW1lbXljZXJ0cy10ZXN0cy5sb2NhbC9DZXJ0RGF0YS9U" +
                "RVNULUNBLmNydDA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AudGFtZW15Y2VydHMt" +
                "dGVzdHMubG9jYWwvb2NzcA==";
                
            var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();

            aiaExt.AddUri(
                "ldap:///CN=TEST-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration," + 
                "DC=tamemycerts-tests,DC=local?cACertificate?base?objectClass=certificationAuthority"
                );
            aiaExt.AddUri("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crt");
            aiaExt.AddUri("http://ocsp.tamemycerts-tests.local/ocsp", true);

            aiaExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(aiaExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void X509ExtensionCrlDistributionPoint_works_short()
        {
            const string expectedResult =
                "MD8wPaA7oDmGN2h0dHA6Ly9wa2kudGFtZW15Y2VydHMtdGVzdHMubG9jYWwvQ2Vy" +
                "dERhdGEvVEVTVC1DQS5jcmw=";

            var cdpExt = new X509CertificateExtensionCrlDistributionPoint();

            cdpExt.AddUri("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crl");
            cdpExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(cdpExt.RawData).Equals(expectedResult));
        }

        [TestMethod]
        public void X509ExtensionAuthorityInformationAccess_works_short()
        {
            const string expectedResult =
                "MEUwQwYIKwYBBQUHMAKGN2h0dHA6Ly9wa2kudGFtZW15Y2VydHMtdGVzdHMubG9j" +
                "YWwvQ2VydERhdGEvVEVTVC1DQS5jcnQ=";

            var aiaExt = new X509CertificateExtensionAuthorityInformationAccess();

            aiaExt.AddUri("http://pki.tamemycerts-tests.local/CertData/TEST-CA.crt");
            aiaExt.InitializeEncode();

            Assert.IsTrue(Convert.ToBase64String(aiaExt.RawData).Equals(expectedResult));
        }
    }
}