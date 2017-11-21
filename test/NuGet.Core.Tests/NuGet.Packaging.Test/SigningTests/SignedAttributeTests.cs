// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
#if NET46

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NuGet.Packaging.Signing;
using NuGet.Packaging.Signing.DerEncoding;
using NuGet.Test.Utility;
using Test.Utility.Signing;
using Xunit;

namespace NuGet.Packaging.Test
{
    public class SignedAttributeTests
    {
        [Fact]
        public async Task SignedAttribute_Test()
        {
            using (var testCert = TestCertificate.Generate().WithTrust())
            {
                var logger = new TestLogger();
                var signatureProvider = new X509SignatureProvider(timestampProvider: null);

                var request = new SignPackageRequest()
                {
                    Certificate = testCert.Source.Cert
                };

                var manifest = new SignatureManifest(Common.HashAlgorithmName.SHA256, "abc");

                var signature = await signatureProvider.CreateSignatureAsync(request, manifest, logger, CancellationToken.None);

                var attributes = signature.SignedCms.SignerInfos[0].SignedAttributes;
                var attributeOids = new List<string>();

                foreach (var att in attributes)
                {
                    attributeOids.Add(att.Oid.Value);
                }

                attributeOids.Should().Contain(Oids.CommitmentTypeIndication);
            }
        }
    }
}

#endif