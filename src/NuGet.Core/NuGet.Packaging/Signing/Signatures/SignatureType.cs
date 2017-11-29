// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace NuGet.Packaging.Signing
{
    /// <summary>
    /// Indicates author or repository signing.
    /// </summary>
    public enum SignatureType
    {
        /// <summary>
        /// Default unknown value.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Signed by the author.
        /// </summary>
        Author = 1,

        /// <summary>
        /// Signed by the repository.
        /// </summary>
        Repository = 2
    }

    static class SignatureTypeMethods
    {
        public static string GetString(this SignatureType type)
        {
            switch (type)
            {
                case SignatureType.Author:
                    return "Author";
                case SignatureType.Repository:
                    return "Repository";
                default:
                    return "Unknown";
            }
        }
    }
}
