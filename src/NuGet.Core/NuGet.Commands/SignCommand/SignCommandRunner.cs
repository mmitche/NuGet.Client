// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGet.Protocol;

namespace NuGet.Commands
{
    /// <summary>
    /// Command Runner used to run the business logic for nuget sign command
    /// </summary>
    public class SignCommandRunner : ISignCommandRunner
    {
        public async Task<int> ExecuteCommandAsync(SignArgs signArgs)
        {
            var success = true;

            // resolve path into multiple packages if needed.
            var packagesToSign = LocalFolderUtility.ResolvePackageFromPath(signArgs.PackagePath);
            LocalFolderUtility.EnsurePackageFileExists(signArgs.PackagePath, packagesToSign);

            var cert = await GetCertificateAsync(signArgs);

            ValidateCertificate(cert);

            signArgs.Logger.LogInformation(Environment.NewLine);
            signArgs.Logger.LogInformation(string.Format(CultureInfo.CurrentCulture,
                Strings.SignCommandDisplayCertificate,
                $"{Environment.NewLine}{CertificateUtility.X509Certificate2ToString(cert)}"));

            if (!string.IsNullOrEmpty(signArgs.Timestamper))
            {
                signArgs.Logger.LogInformation(string.Format(CultureInfo.CurrentCulture,
                    Strings.SignCommandDisplayTimestamper,
                    $"{Environment.NewLine}{signArgs.Timestamper}{Environment.NewLine}"));
            }

            if (!string.IsNullOrEmpty(signArgs.OutputDirectory))
            {
                signArgs.Logger.LogInformation(string.Format(CultureInfo.CurrentCulture,
                    Strings.SignCommandOutputPath,
                    $"{Environment.NewLine}{signArgs.OutputDirectory}{Environment.NewLine}"));
            }

            var signRequest = GenerateSignPackageRequest(signArgs, cert);
            var signatureProvider = GetSignatureProvider(signArgs);

            foreach (var packagePath in packagesToSign)
            {
                try
                {
                    string outputPath;

                    if (string.IsNullOrEmpty(signArgs.OutputDirectory))
                    {
                        outputPath = packagePath;
                    }
                    else
                    {
                        outputPath = Path.Combine(signArgs.OutputDirectory, Path.GetFileName(packagePath));
                    }

                    await SignPackageAsync(packagePath, outputPath, signArgs, signatureProvider, signRequest);
                }
                catch (Exception e)
                {
                    success = false;
                    ExceptionUtilities.LogException(e, signArgs.Logger);
                }
            }

            if (success)
            {
                signArgs.Logger.LogInformation(Strings.SignCommandSuccess);
            }

            return success ? 0 : 1;
        }

        /// <summary>
        /// Used to validate a user specified certificate.
        /// </summary>
        /// <param name="cert">Certificate to be validated</param>
        private static void ValidateCertificate(X509Certificate2 cert)
        {
            //if (SigningUtility.CertificateHasCngPrivateKey(cert))
            //{
            //    // The private key is CNG
            //    // This is currently not supported by SignedCms.ComputeSignature
            //    throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture,
            //        "The following certificate cannot be used for signing a package as it contains a CNG private key - {0}",
            //        $"{Environment.NewLine}{CertificateUtility.X509Certificate2ToString(cert)}"));
            //}

            if (SigningUtility.CertificateContainsEku(cert, Oids.CodeSigningEkuOid))
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture,
                    "The following certificate cannot be used for signing a package as it does not have Code Signing enhanced key usage - {0}",
                    $"{Environment.NewLine}{CertificateUtility.X509Certificate2ToString(cert)}"));
            }
        }

        /// <summary>
        /// Used to filter certificates before displaying matching certificates.
        /// </summary>
        /// <param name="cert">Certificate to be validated</param>
        /// <returns>Bool indicating if a certificate can be used for signing a package or not.</returns>
        private static bool IsCertificateValid(X509Certificate2 cert)
        {
            var result = true;

            if (SigningUtility.CertificateContainsEku(cert, Oids.CodeSigningEkuOid))
            {
                result = false;
            }

            //if (SigningUtility.CertificateHasCngPrivateKey(cert))
            //{
            //    // The private key is CNG
            //    // This is currently not supported by SignedCms.ComputeSignature
            //    result = false;
            //}

            return result;
        }

        private static ISignatureProvider GetSignatureProvider(SignArgs signArgs)
        {
            Rfc3161TimestampProvider timestampProvider = null;

            if (!string.IsNullOrEmpty(signArgs.Timestamper))
            {
                timestampProvider = new Rfc3161TimestampProvider(new Uri(signArgs.Timestamper));
            }

            return new X509SignatureProvider(timestampProvider);
        }

        private async Task<int> SignPackageAsync(
            string packagePath,
            string outputPath,
            SignArgs signArgs,
            ISignatureProvider signatureProvider,
            SignPackageRequest request)
        {
            var tempFilePath = CopyPackage(packagePath);

            using (var packageWriteStream = File.Open(tempFilePath, FileMode.Open))
            {

                if (signArgs.Overwrite)
                {
                    await RemoveSignatureAsync(signArgs.Logger, signatureProvider, packageWriteStream, signArgs.Token);
                }

                await AddSignatureAsync(signArgs.Logger, signatureProvider, request, packageWriteStream, signArgs.Token);
            }

            OverwritePackage(tempFilePath, outputPath);

            FileUtility.Delete(tempFilePath);

            return 0;
        }

        private static async Task AddSignatureAsync(
            ILogger logger,
            ISignatureProvider signatureProvider,
            SignPackageRequest request,
            FileStream packageWriteStream,
            CancellationToken token)
        {
            using (var package = new SignedPackageArchive(packageWriteStream))
            {
                var signer = new Signer(package, signatureProvider);
                await signer.SignAsync(request, logger, token);
            }
        }

        private static async Task RemoveSignatureAsync(
            ILogger logger,
            ISignatureProvider signatureProvider,
            FileStream packageWriteStream,
            CancellationToken token)
        {
            using (var package = new SignedPackageArchive(packageWriteStream))
            {
                var signer = new Signer(package, signatureProvider);
                await signer.RemoveSignaturesAsync(logger, token);
            }
        }

        private static string CopyPackage(string sourceFilePath)
        {
            var destFilePath = Path.GetTempFileName();
            File.Copy(sourceFilePath, destFilePath, overwrite: true);

            return destFilePath;
        }

        private static void OverwritePackage(string sourceFilePath, string destFilePath)
        {
            File.Copy(sourceFilePath, destFilePath, overwrite: true);
        }

        private SignPackageRequest GenerateSignPackageRequest(SignArgs signArgs, X509Certificate2 certificate)
        {
            return new SignPackageRequest
            {
                Certificate = certificate,
                SignatureHashAlgorithm = signArgs.SignatureHashAlgorithm,
                TimestampHashAlgorithm = signArgs.TimestampHashAlgorithm
            };
        }

        private static async Task<X509Certificate2> GetCertificateAsync(SignArgs signArgs)
        {
            var certFindOptions = new CertificateSourceOptions()
            {
                CertificatePath = signArgs.CertificatePath,
                CertificatePassword = signArgs.CertificatePassword,
                Fingerprint = signArgs.CertificateFingerprint,
                StoreLocation = signArgs.CertificateStoreLocation,
                StoreName = signArgs.CertificateStoreName,
                SubjectName = signArgs.CertificateSubjectName,
                NonInteractive = signArgs.NonInteractive,
                PasswordProvider = signArgs.PasswordProvider,
                Token = signArgs.Token
            };

            // get matching certificates
            var matchingCertCollection = await CertificateProvider.GetCertificatesAsync(certFindOptions);

            if (matchingCertCollection.Count > 1)
            {
#if IS_DESKTOP
                if (signArgs.NonInteractive || !RuntimeEnvironmentHelper.IsWindows)
                {
                    // if on non-windows os or in non interactive mode - display the certs and error out
                    signArgs.Logger.LogInformation(CertificateUtility.X509Certificate2CollectionToString(matchingCertCollection));
                    throw new InvalidOperationException(string.Format(Strings.SignCommandMultipleCertException, nameof(SignArgs.CertificateFingerprint)));
                }
                else
                {
                    // Else launch UI to select
                    matchingCertCollection = X509Certificate2UI.SelectFromCollection(
                        FilterMatchingCertificates(matchingCertCollection),
                        Strings.SignCommandDialogTitle,
                        Strings.SignCommandDialogMessage,
                        X509SelectionFlag.SingleSelection);
                }
#else
                // if on non-windows os or in non interactive mode - display and error out
                signArgs.Logger.LogError(CertificateUtility.X509Certificate2CollectionToString(matchingCertCollection));
                throw new InvalidOperationException(string.Format(Strings.SignCommandMultipleCertException, nameof(SignArgs.CertificateFingerprint)));
#endif
            }

            if (matchingCertCollection.Count == 0)
            {
                throw new InvalidOperationException(Strings.SignCommandNoCertException);
            }

            return matchingCertCollection[0];
        }

        private static X509Certificate2Collection FilterMatchingCertificates(X509Certificate2Collection matchingCollection)
        {
            var filteredCollection = new X509Certificate2Collection();

            foreach(var cert in matchingCollection)
            {
                if (IsCertificateValid(cert))
                {
                    filteredCollection.Add(cert);
                }
            }

            return filteredCollection;
        }
    }
}
