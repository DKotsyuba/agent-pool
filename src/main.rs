//! Rust MCP application; protocol, presentation and deployment have separate boundaries.
/// Serializes fixtures that repeatedly hash the large debug test executable.
#[cfg(all(test, target_os = "linux"))]
static TEST_EXEC_HASH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

mod completion;
mod completion_key;
mod completion_saga;
#[cfg(test)]
mod completion_tests;
mod config;
mod domain;
#[cfg(test)]
mod enrollment_tests;
mod integrations;
#[allow(
    dead_code,
    reason = "The B1 adapter retains exact-key recovery helpers"
)]
mod managed_bridge;
#[allow(
    dead_code,
    reason = "The managed codec also defines shared protocol fingerprints"
)]
mod managed_codec;
mod managed_egress;
mod managed_enrollment;
mod managed_ingress;
#[allow(
    dead_code,
    reason = "The R2 client retains authenticated exact-key recovery operations"
)]
mod managed_run;
mod managed_session;
#[allow(
    dead_code,
    reason = "The managed state model retains explicit durable recovery transitions"
)]
mod managed_state;
mod observer;
mod observer_socket;
mod peer_proof;
mod response;
#[allow(
    dead_code,
    reason = "The private hold client retains its list-free v1 discovery and recovery helpers"
)]
mod run_hold;
mod run_status;
mod runtime;
mod store;
mod tools;
use clap::{Parser, Subcommand};
use mcp_presentation::Renderer;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext,
};
use std::{path::PathBuf, process::ExitCode, sync::Arc};

/// Private catalog cache lifetime in milliseconds for modern MCP requests.
const TOOLS_LIST_TTL_MS: u64 = 60_000;

/// Command-line entry point; endpoint configuration is explicit and never inferred from identity variables.
#[derive(Parser)]
#[command(version, about = concat!(env!("CARGO_PKG_NAME"), " MCP server"))]
struct Cli {
    /// Selected operator or MCP command.
    #[command(subcommand)]
    command: Commands,
}
/// Explicit service, MCP and family delivery commands.
#[derive(Subcommand)]
enum Commands {
    /// Read owner projections from an existing resident using one structured stdin request.
    Observe {
        /// Explicit absolute config containing the separately provisioned observer credential.
        #[arg(long, conflicts_with = "socket")]
        config: Option<PathBuf>,
        /// Absolute group-accessible observer socket; needs no config or credential.
        #[arg(long, requires = "server_uid")]
        socket: Option<PathBuf>,
        /// Required UID of the resident serving `--socket`.
        #[arg(long, requires = "socket")]
        server_uid: Option<u32>,
    },
    /// Run the stdio frontend; missing configuration still permits catalog and product identity.
    Mcp {
        /// Explicit private resident/Bridge configuration file; absent disables pool calls.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Own the persistent local pool store, socket and background delivery worker.
    Serve {
        /// Explicit validated endpoint and credential configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Explicitly approve verified Run and Bridge build or credential changes for existing routes.
    Repin {
        /// Explicit validated configuration for the stopped resident and candidate services.
        #[arg(long)]
        config: PathBuf,
    },
    /// Check local resources; an optional owner grant reads resident capacity.
    Doctor {
        /// Request JSON diagnostics (the current output is always JSON).
        #[arg(long)]
        json: bool,
        /// Explicit config with the separate owner observer grant for managed headroom.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Export the actual registry or inspect unimplemented tool stubs.
    Contract {
        /// Selected nested command.
        #[command(subcommand)]
        command: ContractCommand,
    },
    /// Install a verified single-binary bundle. Does not restart services.
    SelfInstall {
        /// Verified family bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// Existing managed installation home.
        #[arg(long)]
        home: PathBuf,
        /// Directory containing the managed executable link.
        #[arg(long)]
        bin_dir: PathBuf,
    },
    /// Select a retained compatible installation.
    Releases {
        /// Selected nested command.
        #[command(subcommand)]
        command: ReleaseCommand,
    },
}
/// Read-only embedded tool contract commands.
#[derive(Subcommand)]
enum ContractCommand {
    /// Print the authoritative embedded tool registry.
    Export,
    /// Print currently incomplete tool names.
    Readiness,
}
/// Existing family installation selection commands.
#[derive(Subcommand)]
enum ReleaseCommand {
    /// Activate an already retained compatible version.
    Use {
        /// Exact retained semantic version.
        version: String,
        /// Existing managed installation home.
        #[arg(long)]
        home: PathBuf,
        /// Directory containing the managed executable link.
        #[arg(long)]
        bin_dir: PathBuf,
    },
}
/// Stateless MCP frontend backed by the separately owned persistent resident.
#[derive(Clone)]
struct Handler {
    /// Embedded product identity renderer.
    identity: Arc<Renderer>,
    /// Safe response templates shared across concurrent MCP calls.
    templates: Arc<response::Templates>,
    /// Static tool catalog, available without service configuration.
    catalog: Vec<Tool>,
    /// Operator-supplied configuration path, never a caller identity source.
    config: Option<PathBuf>,
    /// Admission bound for concurrent native assertion exchanges in this frontend.
    calls: Arc<tokio::sync::Semaphore>,
}
impl Handler {
    /// Validates embedded presentation/catalog resources; performs no service or credential I/O.
    fn new(config: Option<PathBuf>) -> Result<Self, &'static str> {
        let identity = Renderer::new().map_err(|_| "presentation_setup_failed")?;
        let templates = response::Templates::new(&tools::templates())?;
        let catalog = serde_json::from_value(serde_json::Value::Array(tools::definitions()))
            .map_err(|_| "catalog_invalid")?;
        Ok(Self {
            identity: Arc::new(identity),
            templates: Arc::new(templates),
            catalog,
            config,
            calls: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
}
impl ServerHandler for Handler {
    /// Reports protocol capabilities and instructions without claiming service or live qualification.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
            .with_instructions("Use get_status for product identity. Pool calls require a current authenticated native invocation and configured resident. Durable admission is separate from external delivery and agent completion.")
    }
    /// Return the static catalog; modern requests cache it privately for 60 seconds.
    /// Pagination is unused; legacy sessions retain their original wire fields.
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = ListToolsResult::with_all_items(self.catalog.clone());
        if context
            .protocol_version()
            .is_some_and(|version| version.as_str() >= ProtocolVersion::V_2026_07_28.as_str())
        {
            result = result
                .with_ttl_ms(TOOLS_LIST_TTL_MS)
                .with_cache_scope(CacheScope::Private);
        }
        Ok(result)
    }
    /// Routes one actual call, preserving protected metadata and requiring fresh authentication for Pool.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        // rmcp 3.4 moves the ORIGINAL wire params._meta into RequestContext before
        // dispatch (service.rs); request.meta is empty here. This is not a fallback
        // identity. The native adapter must still authenticate its protected claims.
        let original_meta = serde_json::to_value(&context.meta)
            .map_err(|_| McpError::new(ErrorCode::INVALID_PARAMS, "Invalid tool metadata", None))?;
        let args = serde_json::Value::Object(request.arguments.unwrap_or_default());
        if request.name == "get_status" {
            return tools::call(&request.name, args, &self.identity, &self.templates)
                .await
                .map(Into::into)
                .ok_or_else(|| McpError::new(ErrorCode::METHOD_NOT_FOUND, "Unknown tool", None));
        }
        if !self.catalog.iter().any(|tool| tool.name == request.name) {
            return Err(McpError::new(
                ErrorCode::METHOD_NOT_FOUND,
                "Unknown tool",
                None,
            ));
        }
        let Ok(_permit) = self.calls.try_acquire() else {
            return Ok(tools::present(Err(domain::Fault::Unavailable), &self.templates).into());
        };
        let command = managed_codec::normalize_command(
            serde_json::json!({"name":request.name,"arguments":args}),
        )
        .map(|(command, _)| command);
        let result = match (command, self.config.as_deref()) {
            (Ok(command), Some(path)) => runtime::frontend(&command, original_meta, path).await,
            (Err(_), _) => Err(domain::Fault::Invalid),
            (_, None) => Err(domain::Fault::Unavailable),
        };
        Ok(tools::present(result, &self.templates).into())
    }
}
/// Prints one operator-facing JSON result; never used for MCP protocol output.
#[allow(clippy::print_stdout, reason = "Explicit CLI branch, never MCP output")]
fn print_json(value: impl serde::Serialize) -> ExitCode {
    match serde_json::to_string_pretty(&value) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("CLI serialization failed");
            ExitCode::FAILURE
        }
    }
}
/// Selects only a supported target for local installation and retained-version activation.
fn installation_target() -> family_delivery::Result<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        Ok("x86_64-unknown-linux-gnu")
    } else {
        Err("unsupported installation target".into())
    }
}
/// Release qualification recorded in the embedded family manifest, so
/// `doctor` and `get_status` report the same value the release tooling reads.
/// An unreadable manifest fails closed to `not_verified`.
fn qualification() -> &'static str {
    static QUALIFICATION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    QUALIFICATION.get_or_init(|| {
        toml::from_str::<toml::Value>(include_str!("../family.toml"))
            .ok()
            .and_then(|family| {
                family
                    .get("qualification")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "not_verified".to_owned())
    })
}

/// Dispatches explicit CLI work; stdio shutdown affects only its frontend, never the resident.
#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Observe {
            config,
            socket,
            server_uid,
        } => {
            let source = match (&config, &socket, server_uid) {
                (Some(path), None, None) => Some(observer::Source::Config(path)),
                (None, Some(path), Some(server_uid)) => {
                    Some(observer::Source::Socket { path, server_uid })
                }
                _ => None,
            };
            observer::cli(source).await
        }
        Commands::SelfInstall {
            bundle,
            home,
            bin_dir,
        } => match installation_target().and_then(|target| {
            family_delivery::install(&bundle, &home, &bin_dir, env!("CARGO_PKG_NAME"), target)
        }) {
            Ok(m) => print_json(m),
            Err(e) => {
                eprintln!("install: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Releases {
            command:
                ReleaseCommand::Use {
                    version,
                    home,
                    bin_dir,
                },
        } => match installation_target().and_then(|target| {
            family_delivery::use_version(&home, &bin_dir, &version, env!("CARGO_PKG_NAME"), target)
        }) {
            Ok(m) => print_json(m),
            Err(e) => {
                eprintln!("activate: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Doctor { json: _, config } => {
            let ready = Handler::new(None).is_ok();
            let mut report = serde_json::json!({"product":env!("CARGO_PKG_NAME"),"version":env!("CARGO_PKG_VERSION"),
                "local_ready":ready,"release_qualification":qualification(),"incomplete_tools":tools::incomplete()});
            let mut capacity_ready = true;
            if let Some(path) = config {
                let request = observer::Request {
                    schema_version: 1,
                    operation: observer::Operation::ManagedCapacity(observer::IdentityParams {}),
                };
                match observer::frontend(request, &path).await {
                    Ok(observer::Envelope {
                        data: Some(observer::Data::ManagedCapacity(capacity)),
                        error: None,
                        ..
                    }) => {
                        report["managed_capacity"] =
                            serde_json::to_value(capacity).unwrap_or(serde_json::Value::Null);
                        capacity_ready = !report["managed_capacity"].is_null();
                    }
                    _ => {
                        report["managed_capacity"] = serde_json::json!({"state":"unavailable"});
                        capacity_ready = false;
                    }
                }
            }
            let output = print_json(report);
            if ready && capacity_ready {
                output
            } else {
                ExitCode::from(2)
            }
        }
        Commands::Contract {
            command: ContractCommand::Export,
        } => match Handler::new(None) {
            Ok(h) => print_json(h.catalog),
            Err(e) => {
                eprintln!("contract: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Contract {
            command: ContractCommand::Readiness,
        } => print_json(tools::incomplete()),
        Commands::Serve { config } => match runtime::serve(&config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("resident: {error}");
                ExitCode::FAILURE
            }
        },
        Commands::Repin { config } => match runtime::repin(&config).await {
            Ok((bridge, run)) => print_json(serde_json::json!({
                "bridge_pin_generation": bridge,
                "run_pin_generation": run,
            })),
            Err(error) => {
                eprintln!("repin: {error}");
                ExitCode::FAILURE
            }
        },
        Commands::Mcp { config } => {
            let h = match Handler::new(config) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("startup: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match h.serve(rmcp::transport::stdio()).await {
                Ok(service) => match service.waiting().await {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(_) => ExitCode::FAILURE,
                },
                // rmcp 3.9 answers `server/discover` as a bootstrap probe and keeps waiting for
                // a lifecycle, so stdin EOF after it is a clean client disconnect.
                Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("MCP transport failed");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
