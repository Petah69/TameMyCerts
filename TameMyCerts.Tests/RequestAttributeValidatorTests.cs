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
using System.ComponentModel;
using System.Globalization;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

// TODO: Unit Test for a 1 Minute time frame
// TODO: Unit Test that verifies correct Start and End Date

namespace TameMyCerts.Tests
{
    [TestClass]
    public class RequestAttributeValidatorTests
    {
        private const string DATETIME_RFC2616 = "ddd, d MMM yyyy HH:mm:ss 'GMT'";

        private readonly RequestAttributeValidator _attributeValidator = new RequestAttributeValidator();

        private readonly CertificateRequestValidationResult
            _validationResult = new CertificateRequestValidationResult();

        public RequestAttributeValidatorTests()
        {
            _validationResult.NotBefore = DateTimeOffset.Now;
            _validationResult.NotAfter = DateTimeOffset.Now.AddYears(1);
        }

        internal void PrintResult(CertificateRequestValidationResult validationResult)
        {
            Console.WriteLine("0x{0:X} ({0}) {1}.", validationResult.StatusCode,
                new Win32Exception(validationResult.StatusCode).Message);
            Console.WriteLine(string.Join("\n", validationResult.Description));
        }

        [TestMethod]
        public void Deny_StartDate_invalid()
        {
            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("StartDate", "not a valid datetime");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_INVALID_TIME);
        }

        [TestMethod]
        public void Allow_StartDate_no_flag()
        {
            var caConfig = new CertificationAuthorityConfiguration(0);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("StartDate", "not a valid datetime");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_SUCCESS);
        }

        [TestMethod]
        public void Deny_StartDate_in_the_past()
        {
            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("StartDate", "Wed, 19 Oct 2022 20:00:00 GMT");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_INVALID_TIME);
        }

        [TestMethod]
        public void Deny_StartDate_after_NotAfter()
        {
            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("StartDate", "Thu, 31 Dec 2099 20:00:00 GMT");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_INVALID_TIME);
        }

        [TestMethod]
        public void Allow_StartDate()
        {
            var startDate = DateTimeOffset.Now.AddDays(1);

            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTEENDDATE);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("StartDate",
                startDate.ToString(DATETIME_RFC2616, CultureInfo.InvariantCulture.DateTimeFormat));

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_SUCCESS);

            // TODO: Compare actual value
        }

        [TestMethod]
        public void Deny_invalid_flags()
        {
            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2);
            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("saN", "doesnt-matter");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsTrue(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.NTE_FAIL);
        }

        [TestMethod]
        public void Allow_valid_flags()
        {
            var caConfig = new CertificationAuthorityConfiguration(0);

            var validationResult = _validationResult;
            validationResult.RequestAttributes.Add("saN", "doesnt-matter");

            validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_SUCCESS);
        }

        [TestMethod]
        public void Deny_invalid_flags_no_attribute()
        {
            var caConfig = new CertificationAuthorityConfiguration(EditFlag.EDITF_ATTRIBUTESUBJECTALTNAME2);

            var validationResult = _attributeValidator.VerifyRequest(_validationResult, caConfig);

            PrintResult(validationResult);

            Assert.IsFalse(validationResult.DeniedForIssuance);
            Assert.IsTrue(validationResult.StatusCode == WinError.ERROR_SUCCESS);
        }
    }
}