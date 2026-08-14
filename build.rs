use std::{
    error::Error,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use reqwest::blocking::Client;
use zip::ZipArchive;

// Change these human-readable references when updating the protobuf sources.
const ENVOY_TAG: &str = "v1.39.0";
const PROTOBUF_TAG: &str = "v3.21.12";

struct Archive {
    name: String,
    url: String,
    strip_prefix: String,
    source_roots: &'static [&'static str],
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    let archive_dir = out_dir.join("protobuf-archives");
    let proto_dir = out_dir.join("protobuf-sources");
    fs::create_dir_all(&archive_dir)?;
    if proto_dir.exists() {
        fs::remove_dir_all(&proto_dir)?;
    }
    fs::create_dir_all(&proto_dir)?;

    let client = Client::builder()
        .user_agent("envoy-acme-dynmod protobuf build")
        .build()?;
    for archive in archives() {
        let archive_path = archive_dir.join(&archive.name);
        download(&client, &archive, &archive_path)?;
        extract_protos(&archive, &archive_path, &proto_dir)?;
    }

    let sds = proto_dir.join("envoy/service/secret/v3/sds.proto");
    let secret = proto_dir.join("envoy/extensions/transport_sockets/tls/v3/secret.proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .include_file("generated_protos.rs")
        .compile_protos(&[sds, secret], &[proto_dir])?;
    Ok(())
}

fn archives() -> [Archive; 5] {
    [
        tagged_archive("envoyproxy/envoy", ENVOY_TAG, "api", &["envoy"]),
        tagged_archive(
            "protocolbuffers/protobuf",
            PROTOBUF_TAG,
            "src",
            &["google/protobuf"],
        ),
        tagged_archive("bufbuild/protoc-gen-validate", "v1.3.3", "", &["validate"]),
        branch_archive("cncf/xds", "main", "", &["udpa", "xds"]),
        branch_archive(
            "googleapis/googleapis",
            "master",
            "",
            &["google/api", "google/rpc"],
        ),
    ]
}

fn tagged_archive(
    repository: &str,
    tag: &str,
    source_prefix: &str,
    source_roots: &'static [&'static str],
) -> Archive {
    archive(repository, "tags", tag, source_prefix, source_roots)
}

fn branch_archive(
    repository: &str,
    branch: &str,
    source_prefix: &str,
    source_roots: &'static [&'static str],
) -> Archive {
    archive(repository, "heads", branch, source_prefix, source_roots)
}

fn archive(
    repository: &str,
    reference_kind: &str,
    reference: &str,
    source_prefix: &str,
    source_roots: &'static [&'static str],
) -> Archive {
    let project = repository
        .rsplit('/')
        .next()
        .expect("repository has a name");
    let extracted_reference = reference.strip_prefix('v').unwrap_or(reference);
    let root = format!("{project}-{extracted_reference}");
    Archive {
        name: format!("{project}-{reference}.zip"),
        url: format!(
            "https://github.com/{repository}/archive/refs/{reference_kind}/{reference}.zip"
        ),
        strip_prefix: if source_prefix.is_empty() {
            root
        } else {
            format!("{root}/{source_prefix}")
        },
        source_roots,
    }
}

fn download(client: &Client, archive: &Archive, destination: &Path) -> Result<(), Box<dyn Error>> {
    let temporary = destination.with_extension("zip.tmp");
    let mut response = client.get(&archive.url).send()?.error_for_status()?;
    let mut file = File::create(&temporary)?;
    io::copy(&mut response, &mut file)?;
    file.sync_all()?;
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)?;
    Ok(())
}

fn extract_protos(
    archive: &Archive,
    archive_path: &Path,
    destination: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut zip = ZipArchive::new(File::open(archive_path)?)?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let Some(path) = entry.enclosed_name() else {
            return Err(format!("unsafe path in {}", archive.name).into());
        };
        let Ok(relative) = path.strip_prefix(&archive.strip_prefix) else {
            continue;
        };
        if relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("proto")
            || !archive
                .source_roots
                .iter()
                .any(|root| relative.starts_with(root))
        {
            continue;
        }

        let output = destination.join(relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = File::create(output)?;
        io::copy(&mut entry, &mut file)?;
    }
    Ok(())
}
