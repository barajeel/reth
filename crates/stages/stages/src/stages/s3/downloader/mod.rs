//! Provides functionality for downloading files in chunks from a remote source. It supports
//! concurrent downloads, resumption of interrupted downloads, and verification of the downloaded
//! file integrity.

mod downloader;
mod error;
mod meta;
mod worker;

pub(crate) use downloader::fetch;
