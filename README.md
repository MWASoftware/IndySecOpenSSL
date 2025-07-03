# Indy TLS for OpenSSL

This project implements TLS and Hash functionalities for Indy using OpenSSL as the backend library.

It is split off from the main Indy library so it can be updated independantly to the latest version of OpenSSL.

It should be usable as an additional package/dropin to Indy, as long as it remains compatible with Indy's SSLIOHandler and IdFIPS interfaces.

In theory, once this project is stable, the corresponding files can be removed from Indy's main Protocols package, the USE_OPENSSL conditional can be removed from Indy's source files, etc.

Not sure at this time whether this project will stay as an independant repo, or if it will eventually be merged back into the main Indy repo.

## License

This project is dual-licensed under the terms of the Indy Modified BSD License and Indy MPL License.
You can choose between one of them if you use this work.

`SPDX-License-Identifier: LicenseRef-IndyBSD OR MPL-1.1`