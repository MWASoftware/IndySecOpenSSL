# Indy TLS for OpenSSL

This repo provides the IndySecOpenSSL package for both Delphi and Lazarus/fpc.

This package provides a new (optional) OpenSSL package separate from Indy's 
"protocols" package and adds support for OpenSSL 3.0 and later. It may be used
as an add-on the Indy 10.6 or the forthcoming Indy 10.7 releases.

The IndySecOpenSSL package's purpose is to provide Indy users with an upgrade path to 
the use of current OpenSSL (3.x) libraries with the minimum of change. This includes users 
that use the existing version of Indy bundled with Delphi and the version provided with 
the Lazarus Online Package Manager.

For more information on the installation and use of the package please read the
comprehensive User Guide provided in the docs subdirectory. New users should pay
particular attention to the installation instructions and guidance on installation
of the OpenSSL shared libraries (DLLs) included in the User Guide.

##Overview

Indy itself is a well-known internet component suite for Delphi, C++Builder, and 
Free Pascal providing both low-level support (TCP, UDP, raw sockets) and over a 120 
higher level protocols (SMTP, POP3, NNT, HTTP, FTP) for building both client and server 
applications. See https://github.com/IndySockets/Indy.

However, at the time of writing, the current release of Indy (10.6.x), only supports 
the obsolete OpenSSL 1.0.2 library. This release of OpenSSL no longer receives updates
from the OpenSSL project and only supports the the TLS 1.2 protocol. 
This is a serious problem for Indy users that need to use an up-to-date release of 
OpenSSL (3.x) which is both supported and supports the current TLS 1.3 protocol.

This add-on overcomes these problems and adds OpenSSL 3.x support to Indy whilst being 
backwards compatible and continues to support OpenSSL 1.0.2 and 1.1.1.

It is currently expected that OpenSSL support will be removed in Indy 10.7 itself and provided in
a separate package. IndySecOpenSSL is such a package.

In terms of the deployment of  user applications that use the IndySecOpenSSL package, 
three link models are supported.

   * Dynamic Library Load (the default and the approach used in previous versions)
   * compile time linkage to a shared (.so or .dll) library (OpenSSL 3.x only)
   * compile time linkage to a static library (FPC only with gcc compiled OpenSSL).


## License

This project is dual-licensed under the terms of the Indy Modified BSD License and Indy MPL License.
You can choose between one of them if you use this work.

SPDX-License-Identifier: LicenseRef-IndyBSD OR MPL-1.1

