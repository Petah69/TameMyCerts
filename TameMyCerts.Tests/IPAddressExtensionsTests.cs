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

using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TameMyCerts.ClassExtensions;

namespace TameMyCerts.Tests
{
    [TestClass]
    public class IPAddressExtensionsTests
    {
        [TestMethod]
        public void IP_is_in_subnet_class_a()
        {
            Assert.IsTrue(IPAddress.Parse("10.0.0.0").IsInRange("10.0.0.0/8"));
            Assert.IsTrue(IPAddress.Parse("10.0.0.1").IsInRange("10.0.0.0/8"));
            Assert.IsTrue(IPAddress.Parse("10.255.255.255").IsInRange("10.0.0.0/8"));
            Assert.IsFalse(IPAddress.Parse("11.0.0.1").IsInRange("10.0.0.0/8"));
        }

        [TestMethod]
        public void IP_is_in_subnet_class_b()
        {
            Assert.IsTrue(IPAddress.Parse("172.16.0.0").IsInRange("172.16.0.0/12"));
            Assert.IsTrue(IPAddress.Parse("172.16.0.1").IsInRange("172.16.0.0/12"));
            Assert.IsTrue(IPAddress.Parse("172.31.255.255").IsInRange("172.16.0.0/12"));
            Assert.IsFalse(IPAddress.Parse("172.32.0.1").IsInRange("172.16.0.0/16"));
        }

        [TestMethod]
        public void IP_is_in_subnet_class_c()
        {
            Assert.IsTrue(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/16"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/16"));
            Assert.IsTrue(IPAddress.Parse("192.168.255.255").IsInRange("192.168.0.0/16"));
            Assert.IsFalse(IPAddress.Parse("192.169.0.1").IsInRange("192.168.0.0/16"));
        }

        [TestMethod]
        public void IP_is_in_subnet_class_c_24()
        {
            Assert.IsTrue(IPAddress.Parse("192.168.0.0").IsInRange("192.168.0.0/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("192.168.0.0/24"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.255").IsInRange("192.168.0.0/24"));
            Assert.IsFalse(IPAddress.Parse("192.168.1.1").IsInRange("192.168.0.0/24"));
        }

        [TestMethod]
        public void IP_is_in_subnet_any()
        {
            Assert.IsTrue(IPAddress.Parse("0.0.0.0").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("10.0.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("172.16.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsTrue(IPAddress.Parse("192.168.0.1").IsInRange("0.0.0.0/0"));
            Assert.IsFalse(IPAddress.Parse("255.255.255.255").IsInRange("0.0.0.0/32"));
        }
    }
}