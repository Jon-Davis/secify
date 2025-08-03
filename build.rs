fn main() {
    prost_build::compile_protos(&["secify-lib/src/header.proto"], &["secify-lib/src/"]).unwrap();
}
