// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Runtime.InteropServices;
#if IS_DESKTOP
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NuGet.Common;
#endif

namespace NuGet.Packaging.Signing
{
    internal static class NativeUtilities
    {
        internal static void SafeFree(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        internal static void ThrowIfFailed(bool result)
        {
            if (!result)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }
#if IS_DESKTOP
        internal static SignedCms NativeSign(byte[] data, X509Certificate2 certificate, CngKey privateKey, CryptographicAttributeObjectCollection attributes, Common.HashAlgorithmName hashAlgorithm)
        {
            using (privateKey)
            using (var hb = new HeapBlockRetainer())
            {
                var chain = new X509Chain();

                // Skipping a bunch of chain building options we should normally set otherwise
                chain.Build(certificate);

                var certificateBlobs = new BLOB[chain.ChainElements.Count];

                for (var i = 0; i < chain.ChainElements.Count; ++i)
                {
                    var cert = chain.ChainElements[i].Certificate;
                    var context = Marshal.PtrToStructure<CERT_CONTEXT>(cert.Handle);

                    certificateBlobs[i] = new BLOB() { cbData = context.cbCertEncoded, pbData = context.pbCertEncoded };
                }

                byte[] encodedData;
                var signerInfo = CreateEncodeInfo(certificate, privateKey, attributes, hashAlgorithm, hb);

                var signedInfo = new CMSG_SIGNED_ENCODE_INFO();
                signedInfo.cbSize = Marshal.SizeOf(signedInfo);
                signedInfo.cSigners = 1;

                using (var signerInfoHandle = new SafeLocalAllocHandle(Marshal.AllocHGlobal(Marshal.SizeOf(signerInfo))))
                {
                    Marshal.StructureToPtr(signerInfo, signerInfoHandle.DangerousGetHandle(), fDeleteOld: false);

                    signedInfo.rgSigners = signerInfoHandle.DangerousGetHandle();
                    signedInfo.cCertEncoded = certificateBlobs.Length;

                    using (var certificatesHandle = new SafeLocalAllocHandle(Marshal.AllocHGlobal(Marshal.SizeOf(certificateBlobs[0]) * certificateBlobs.Length)))
                    {
                        for (var i = 0; i < certificateBlobs.Length; ++i)
                        {
                            Marshal.StructureToPtr(certificateBlobs[i], new IntPtr(certificatesHandle.DangerousGetHandle().ToInt64() + Marshal.SizeOf(certificateBlobs[i]) * i), fDeleteOld: false);
                        }

                        signedInfo.rgCertEncoded = certificatesHandle.DangerousGetHandle();

                        var hMsg = NativeMethods.CryptMsgOpenToEncode(
                            NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                            dwFlags: 0,
                            dwMsgType: NativeMethods.CMSG_SIGNED,
                            pvMsgEncodeInfo: ref signedInfo,
                            pszInnerContentObjID: null,
                            pStreamInfo: IntPtr.Zero);

                        ThrowIfFailed(!hMsg.IsInvalid);

                        ThrowIfFailed(NativeMethods.CryptMsgUpdate(
                            hMsg,
                            data,
                            (uint)data.Length,
                            fFinal: true));

                        uint valueLength = 0;

                        ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                            hMsg,
                            CMSG_GETPARAM_TYPE.CMSG_CONTENT_PARAM,
                            dwIndex: 0,
                            pvData: null,
                            pcbData: ref valueLength));

                        encodedData = new byte[(int)valueLength];

                        ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                            hMsg,
                            CMSG_GETPARAM_TYPE.CMSG_CONTENT_PARAM,
                            dwIndex: 0,
                            pvData: encodedData,
                            pcbData: ref valueLength));
                    }
                }

                var cms = new SignedCms();

                cms.Decode(encodedData);

                return cms;
            }
        }

        private unsafe static CMSG_SIGNER_ENCODE_INFO CreateEncodeInfo(
            X509Certificate2 certificate,
            CngKey privateKey,
            CryptographicAttributeObjectCollection attributes,
            Common.HashAlgorithmName hashAlgorithm,
            HeapBlockRetainer hb)
        {
            var signerInfo = new CMSG_SIGNER_ENCODE_INFO();
            signerInfo.cbSize = (uint)Marshal.SizeOf(signerInfo);
            signerInfo.pCertInfo = Marshal.PtrToStructure<CERT_CONTEXT>(certificate.Handle).pCertInfo;
            signerInfo.hCryptProvOrhNCryptKey = privateKey.Handle.DangerousGetHandle();
            // DwKeySpec is not used when hCryptProvOrhNCryptKey is used.
            signerInfo.dwKeySpec = 1;
            signerInfo.HashAlgorithm.pszObjId = hashAlgorithm.ConvertToOidString();

            if (attributes.Count != 0)
            {
                signerInfo.cAuthAttr = attributes.Count;

                checked
                {
                    var totalLength = 0;
                    var cryptAttrSize = Marshal.SizeOf(typeof(CRYPT_ATTRIBUTE));
                    var cryptBlobSize = Marshal.SizeOf(typeof(CRYPT_INTEGER_BLOB_INTPTR));

                    // First compute the total serialized unmanaged memory size needed.
                    // For each attribute, we add the CRYPT_ATTRIBUTE size, the size
                    // needed for the ObjId, and the size needed for all the values
                    // inside each attribute which is computed in inner loop.
                    foreach (var attribute in attributes)
                    {
                        totalLength += cryptAttrSize;  // sizeof(CRYPT_ATTRIBUTE)
                        totalLength += attribute.Oid.Value.Length + 1;  // strlen(pszObjId) + 1

                        // For each value within the attribute, we add the CRYPT_ATTR_BLOB size and 
                        // the actual size needed for the data.
                        foreach (var attributeValue in attribute.Values)
                        {
                            totalLength += cryptBlobSize;   // Add CRYPT_ATTR_BLOB size
                            totalLength += attributeValue.RawData.Length; // Data size
                        }
                    }

                    var pCryptAttributes = (CRYPT_ATTRIBUTE*)hb.Alloc(totalLength);
                    var pCryptAttribute = pCryptAttributes;
                    var pAttrData = new IntPtr((long)pCryptAttribute + (cryptAttrSize * attributes.Count));

                    foreach (var attribute in attributes)
                    {
                        var pszObjId = (byte*)pAttrData;
                        var objId = new byte[attribute.Oid.Value.Length + 1];
                        var pDataBlob = (CRYPT_INTEGER_BLOB_INTPTR*)(pszObjId + objId.Length);

                        // CRYPT_ATTRIBUTE.pszObjId
                        pCryptAttribute->pszObjId = (IntPtr)pszObjId;

                        // CRYPT_ATTRIBUTE.cValue
                        pCryptAttribute->cValue = (uint)attribute.Values.Count;

                        // CRYPT_ATTRIBUTE.rgValue
                        pCryptAttribute->rgValue = (IntPtr) pDataBlob;

                        // ObjId - The actual dotted value of the OID.
                        Encoding.ASCII.GetBytes(attribute.Oid.Value, 0, attribute.Oid.Value.Length, objId, 0);
                        Marshal.Copy(objId, 0, pCryptAttribute->pszObjId, objId.Length);

                        // cValue of CRYPT_INTEGER_BLOB_INTPTR followed by cValue of actual data.
                        var pbEncodedData = new IntPtr((long)pDataBlob + (attribute.Values.Count * cryptBlobSize));
                        foreach (var value in attribute.Values)
                        {
                            // Retrieve encoded data.
                            var encodedData = value.RawData;

                            // Write data
                            if (encodedData.Length > 0)
                            {
                                // CRYPT_ATTR_BLOB.cbData
                                pDataBlob->cbData = (uint)encodedData.Length;

                                // CRYPT_ATTR_BLOB.pbData
                                pDataBlob->pbData = pbEncodedData;

                                Marshal.Copy(encodedData, 0, pbEncodedData, encodedData.Length);
                                pbEncodedData = new IntPtr((long)pbEncodedData + encodedData.Length);
                            }

                            // Advance pointer.
                            pDataBlob++;
                        }

                        // Advance pointers.
                        pCryptAttribute++;
                        pAttrData = pbEncodedData;
                    }

                    signerInfo.rgAuthAttr = new IntPtr(pCryptAttributes);
                }
            }
            return signerInfo;
        }
#endif
    }
}