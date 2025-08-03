fn main() {
    // Use prost-build with protoc bundled to avoid requiring system protoc installation
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    
    match config.compile_protos(&["src/header.proto"], &["src/"]) {
        Ok(_) => println!("cargo:rerun-if-changed=src/header.proto"),
        Err(e) => {
            eprintln!("Failed to compile protobuf: {}", e);
            eprintln!("Note: This requires protoc to be installed or available in PATH");
            std::process::exit(1);
        }
    }
}
