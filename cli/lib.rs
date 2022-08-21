#![deny(warnings)]
//#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::from_over_into)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate log;

pub mod args;
pub(crate) mod auth_tokens;
mod cache;
mod cdp;
pub(crate) mod checksum;
mod compat;
pub(crate) mod deno_dir;
pub(crate) mod diagnostics;
mod diff;
mod display;
mod emit;
pub mod errors;
pub mod file_fetcher;
pub mod file_watcher;
pub mod fmt_errors;
pub(crate) mod fs_util;
pub(crate) mod graph_util;
pub(crate) mod http_cache;
pub(crate) mod http_util;
pub(crate) mod lockfile;
mod logger;
mod lsp;
pub mod module_loader;
#[allow(unused)]
mod npm;
pub mod ops;
pub mod proc_state;
mod resolver;
mod standalone;
pub(crate) mod text_encoding;
mod tools;
pub(crate) mod tsc;
mod unix_util;
pub mod version;
mod windows_util;
pub mod worker;

use crate::args::flags_from_vec;
use crate::args::BenchFlags;
use crate::args::BundleFlags;
use crate::args::CacheFlags;
use crate::args::CheckFlags;
use crate::args::CompileFlags;
use crate::args::CompletionsFlags;
use crate::args::CoverageFlags;
use crate::args::DenoSubcommand;
use crate::args::DocFlags;
use crate::args::EvalFlags;
use crate::args::Flags;
use crate::args::FmtFlags;
use crate::args::InfoFlags;
use crate::args::InstallFlags;
use crate::args::LintFlags;
use crate::args::ReplFlags;
use crate::args::RunFlags;
use crate::args::TaskFlags;
use crate::args::TestFlags;
use crate::args::TypeCheckMode;
use crate::args::UninstallFlags;
use crate::args::UpgradeFlags;
use crate::args::VendorFlags;
use crate::cache::TypeCheckCache;
use crate::emit::TsConfigType;
use crate::file_fetcher::File;
use crate::file_watcher::ResolutionResult;
use crate::fmt_errors::format_js_error;
use crate::graph_util::graph_lock_or_exit;
use crate::graph_util::graph_valid;
use crate::proc_state::ProcState;
use crate::resolver::ImportMapResolver;
use crate::resolver::JsxResolver;

use args::CliOptions;
use deno_ast::MediaType;
use deno_core::error::generic_error;
use deno_core::error::AnyError;
use deno_core::error::JsError;
use deno_core::futures::future::FutureExt;
use deno_core::futures::Future;
use deno_core::parking_lot::RwLock;
use deno_core::resolve_url_or_path;
use deno_core::serde_json;
use deno_core::serde_json::json;
use deno_core::v8_set_flags;
use deno_core::ModuleSpecifier;
use deno_runtime::colors;
use deno_runtime::permissions::Permissions;
use deno_runtime::tokio_util::run_local;
use log::debug;
use log::info;
use std::env;
use std::io::Read;
use std::io::Write;
use std::iter::once;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use worker::create_main_worker;

pub fn get_types(unstable: bool) -> String {
  let mut types = vec![
    crate::tsc::DENO_NS_LIB,
    crate::tsc::DENO_CONSOLE_LIB,
    crate::tsc::DENO_URL_LIB,
    crate::tsc::DENO_WEB_LIB,
    crate::tsc::DENO_FETCH_LIB,
    crate::tsc::DENO_WEBGPU_LIB,
    crate::tsc::DENO_WEBSOCKET_LIB,
    crate::tsc::DENO_WEBSTORAGE_LIB,
    crate::tsc::DENO_CRYPTO_LIB,
    crate::tsc::DENO_BROADCAST_CHANNEL_LIB,
    crate::tsc::DENO_NET_LIB,
    crate::tsc::SHARED_GLOBALS_LIB,
    crate::tsc::WINDOW_LIB,
  ];

  if unstable {
    types.push(crate::tsc::UNSTABLE_NS_LIB);
  }

  types.join("\n")
}

pub fn write_to_stdout_ignore_sigpipe(
  bytes: &[u8],
) -> Result<(), std::io::Error> {
  use std::io::ErrorKind;

  match std::io::stdout().write_all(bytes) {
    Ok(()) => Ok(()),
    Err(e) => match e.kind() {
      ErrorKind::BrokenPipe => Ok(()),
      _ => Err(e),
    },
  }
}

pub fn write_json_to_stdout<T>(value: &T) -> Result<(), AnyError>
where
  T: ?Sized + serde::ser::Serialize,
{
  let mut writer = std::io::BufWriter::new(std::io::stdout());
  serde_json::to_writer_pretty(&mut writer, value)?;
  writeln!(&mut writer)?;
  Ok(())
}

fn unwrap_or_exit<T>(result: Result<T, AnyError>) -> T {
  match result {
    Ok(value) => value,
    Err(error) => {
      let error_string = match error.downcast_ref::<JsError>() {
        Some(e) => format_js_error(e),
        None => format!("{:?}", error),
      };
      eprintln!(
        "{}: {}",
        colors::red_bold("error"),
        error_string.trim_start_matches("error: ")
      );
      std::process::exit(1);
    }
  }
}
