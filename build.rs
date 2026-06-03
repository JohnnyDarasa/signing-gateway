fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/grpc")
        .file_descriptor_set_path("src/grpc/signing_descriptor.bin")
        .compile(&["proto/signing.proto"], &["proto"])?;
    Ok(())
}
