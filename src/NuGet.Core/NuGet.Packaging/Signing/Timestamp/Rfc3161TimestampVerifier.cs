// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Linq;

#if IS_DESKTOP
using System.Security.Cryptography.Pkcs;
#endif

using System.Security.Cryptography.X509Certificates;
using NuGet.Common;

namespace NuGet.Packaging.Signing
{
    /// <summary>
    /// Provides convinience method for verification of a RFC 3161 Timestamp.
    /// </summary>
    internal static class Rfc3161TimestampVerifier
    {
        private const long _ticksPerMicroSecond = 10;

#if IS_DESKTOP

        internal static bool ValidateSignerCertificateAgainstTimestamp(
            X509Certificate2 signerCertificate,
            Rfc3161TimestampTokenInfo tstInfo)
        {
            var tstInfoGenTime = tstInfo.Timestamp;
            var tstInfoAccuracy = tstInfo.AccuracyInMicroseconds;
            long tstInfoAccuracyInTicks;

            if (!tstInfoAccuracy.HasValue)
            {
                if (string.Equals(tstInfo.PolicyId, Oids.BaselineTimestampPolicyOid))
                {
                    tstInfoAccuracyInTicks = TimeSpan.TicksPerSecond;
                }
                else
                {
                    tstInfoAccuracyInTicks = 0;
                }
            }
            else
            {
                tstInfoAccuracyInTicks = tstInfoAccuracy.Value * _ticksPerMicroSecond;
            }

            // everything to UTC
            var timestampUpperGenTimeUtcTicks = tstInfoGenTime.AddTicks(tstInfoAccuracyInTicks).UtcTicks;
            var timestampLowerGenTimeUtcTicks = tstInfoGenTime.Subtract(TimeSpan.FromTicks(tstInfoAccuracyInTicks)).UtcTicks;
            var signerCertExpiryUtcTicks = signerCertificate.NotAfter.ToUniversalTime().Ticks;
            var signerCertBeginUtcTicks = signerCertificate.NotBefore.ToUniversalTime().Ticks;

            return timestampUpperGenTimeUtcTicks < signerCertExpiryUtcTicks &&
                timestampLowerGenTimeUtcTicks > signerCertBeginUtcTicks;
        }

        internal static bool TryReadTSTInfoFromSignedCms(
            SignedCms timestampCms,
            out Rfc3161TimestampTokenInfo tstInfo)
        {
            if (timestampCms.ContentInfo.ContentType.Value.Equals(Oids.TSTInfoContentTypeOid))
            {
                tstInfo = new Rfc3161TimestampTokenInfo(timestampCms.ContentInfo.Content);
                return true;
            }
            else
            {
                // return false if the signedCms object does not contain the right ContentType
                tstInfo = null;
                return false;
            }
        }

        internal static bool TryBuildTimestampCertificateChain(X509Certificate2 certificate, X509Certificate2Collection additionalCertificates, out X509Chain chain)
        {
            return SigningUtility.IsCertificateValid(certificate, additionalCertificates, out chain, allowUntrustedRoot: false, checkRevocationMode: X509RevocationMode.Online);
        }

        internal static bool ValidateTimestampEnhancedKeyUsage(X509Certificate2 certificate)
        {
            return SigningUtility.CertificateContainsEku(certificate, Oids.TimeStampingEkuOid);
        }

        internal static bool ValidateTimestampedData(Rfc3161TimestampTokenInfo tstInfo, byte[] data)
        {
            return tstInfo.HasMessageHash(data);
        }

        internal static bool ValidateTimestampAlgorithm(SignedCms timestampSignedCms, SigningSpecifications specifications)
        {
            var timestampSignerInfo = timestampSignedCms.SignerInfos[0];
            return specifications.AllowedHashAlgorithmOids.Contains(timestampSignerInfo.DigestAlgorithm.Value);
        }
#endif
    }
}
