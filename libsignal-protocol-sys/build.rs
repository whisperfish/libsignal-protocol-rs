fn main() {
    let dst = get_cmake_config().build();

    println!("cargo:rustc-link-search={}", dst.display());
    println!("cargo:rustc-link-search={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=signal-protocol-c");
}

// Additional parameters for Android build of libsignal-protocol-c.
const CMAKE_PARAMS_ANDROID: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[
            ("ANDROID_ABI", "arm64-v8a"),
            ("ANDROID_NATIVE_API_LEVEL", "21"),
            (
                "CMAKE_TOOLCHAIN_FILE",
                "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
            ),
        ],
    ),
    (
        "arm",
        &[
            ("ANDROID_ABI", "armeabi-v7a"),
            ("ANDROID_NATIVE_API_LEVEL", "21"),
            (
                "CMAKE_TOOLCHAIN_FILE",
                "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
            ),
        ],
    ),
    (
        "x86",
        &[
            ("ANDROID_ABI", "x86"),
            ("ANDROID_NATIVE_API_LEVEL", "21"),
            (
                "CMAKE_TOOLCHAIN_FILE",
                "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
            ),
        ],
    ),
    (
        "x86_64",
        &[
            ("ANDROID_ABI", "x86_64"),
            ("ANDROID_NATIVE_API_LEVEL", "21"),
            (
                "CMAKE_TOOLCHAIN_FILE",
                "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
            ),
        ],
    ),
];

// Additional parameters for iOS build of libsignal-protocol-c.
const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "arm",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "x86",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
    (
        "x86_64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
];

/// Returns a new cmake::Config for building libsignal-protocol-c.
///
/// It will add platform-specific parameters if needed.
fn get_cmake_config() -> cmake::Config {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut libsignal_cmake = cmake::Config::new("libsignal-protocol-c");

    // Add platform-specific parameters.
    match os.as_ref() {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            for (android_arch, params) in CMAKE_PARAMS_ANDROID {
                if *android_arch == arch {
                    for (name, value) in *params {
                        let value = value
                            .replace("${ANDROID_NDK_HOME}", &android_ndk_home);
                        eprintln!(
                            "android arch={} add {}={}",
                            arch, name, value
                        );
                        libsignal_cmake.define(name, value);
                    }
                }
            }

            libsignal_cmake
        }

        "ios" => {
            for (ios_arch, params) in CMAKE_PARAMS_IOS {
                if *ios_arch == arch {
                    for (name, value) in *params {
                        eprintln!("ios arch={} add {}={}", arch, name, value);
                        libsignal_cmake.define(name, value);
                    }
                }
            }

            // bitcode on
            libsignal_cmake.define("CMAKE_ASM_FLAGS", "-fembed-bitcode");
            libsignal_cmake.cflag("-fembed-bitcode");

            libsignal_cmake
        }

        _ => libsignal_cmake,
    }
}
