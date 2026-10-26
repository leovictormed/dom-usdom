#![no_main]

use dom_chain::UsdomV4BlockPackage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(package) = UsdomV4BlockPackage::from_bytes(bytes) {
        let canonical = package
            .to_bytes()
            .expect("a parsed USDOMBL4 package must remain encodable");
        assert_eq!(canonical.as_slice(), bytes);
        let reparsed = UsdomV4BlockPackage::from_bytes(&canonical)
            .expect("canonical USDOMBL4 bytes must parse again");
        assert_eq!(reparsed, package);
    }
});
