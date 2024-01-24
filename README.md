# Pro-Level Licenses
Obligatory: Based on [this](https://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi/) because the two other people who implemented it in Rust didn't do it very well.

Example in docs!
## Why you should use this crate:
- It provides short licenses
- Easily block shared licenses with the remote blocker
- Completely offline
## Alternatives to this crate:
- If your app is already expected to have some sort of internet connection, just use a remote license checker or account system.
- Digital signatures (I recommend edDSA). It will give longer licenses probably better suited for copy and paste as well as making it impossible to even partially forge a license. Still doesn't check if a license has been used more than once.

Example license: `BWQq-RQNa-kDp6-mJn8-SSEh-UStw-p9+q-krw1-KDH4-mw`

For extra security [obfuscate your binary](https://web.archive.org/web/20240122004026/https://vrls.ws/posts/2023/06/obfuscating-rust-binaries-using-llvm-obfuscator-ollvm/)!

You can generate licenses easily on the command line using our [license generator](https://crates.io/crates/licenses_pro_gen)