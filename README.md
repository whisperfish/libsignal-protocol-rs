# libsignal-protocol-rs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/82a990f6d0b441038ff00c11a685b876)](https://app.codacy.com/app/shekohex/libsignal-protocol-rs?utm_source=github.com&utm_medium=referral&utm_content=Michael-F-Bryan/libsignal-protocol-rs&utm_campaign=Badge_Grade_Settings)
[![Build Status](https://travis-ci.com/Michael-F-Bryan/libsignal-protocol-rs.svg?branch=master)](https://travis-ci.com/Michael-F-Bryan/libsignal-protocol-rs)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FMichael-F-Bryan%2Flibsignal-protocol-rs.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FMichael-F-Bryan%2Flibsignal-protocol-rs?ref=badge_shield)

([API Docs])

A Rust interface to the [Signal Protocol][upstream].

## Examples

The simplest thing you can do with this library is generate a private identity
key. This is normally only ever done once when you first start (sometimes called
*install time*).

```rust,skt-main
// create our global context (for things like crypto and locking)
let ctx = Context::default();

let identity = libsignal_protocol::generate_identity_key_pair(&ctx)?;
```

Next, you'll normally want to generate a bunch of unsigned pre-keys which 
people can use when contacting you, and one signed pre-key.

```rust,skt-main
let ctx = Context::default();

let identity = libsignal_protocol::generate_identity_key_pair(&ctx)?;

let signed_pre_key = libsignal_protocol::generate_signed_pre_key(
    &ctx,
    &identity,
    5,
    SystemTime::now(),
)?;

let start = 123;
let count = 20;

let pre_keys = libsignal_protocol::generate_pre_keys(&ctx, start, count)?
    .collect::<Vec<PreKey>>();
```

A Registration ID should also be created at install time.

```rust,skt-main
let ctx = Context::default();
let extended_range = 42;

let registration_id = libsignal_protocol::generate_registration_id(&ctx, extended_range)?;
```

## Legal things

### Cryptography Notice

This distribution includes cryptographic software. The country in which you
currently reside may have restrictions on the import, possession, use, and/or
re-export to another country, of encryption software. BEFORE using any
encryption software, please check your country's laws, regulations and
policies concerning the import, possession, or use, and re-export of
encryption software, to see if this is permitted. See
<http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security
(BIS), has classified this software as Export Commodity Control Number (ECCN)
5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms. The form and manner of
this distribution makes it eligible for export under the License Exception
ENC Technology Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and source
code.

### License

Copyright 2015-2019 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

Additional Permissions For Submission to Apple App Store: Provided that you
are otherwise in compliance with the GPLv3 for each covered work you convey
(including without limitation making the Corresponding Source available in
compliance with Section 6 of the GPLv3), Open Whisper Systems also grants you
the additional permission to convey through the Apple App Store non-source
executable versions of the Program as incorporated into each applicable
covered work as Executable Versions only under the Mozilla Public License
version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/).

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FMichael-F-Bryan%2Flibsignal-protocol-rs.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FMichael-F-Bryan%2Flibsignal-protocol-rs?ref=badge_large)

[API Docs]: https://michael-f-bryan.github.io/libsignal-protocol-rs
[upstream]: https://github.com/signalapp/libsignal-protocol-c