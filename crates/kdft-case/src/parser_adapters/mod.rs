//! Shared contracts for locked, offline specialist parser adapters.
//!
//! This module intentionally contains no process launcher and performs no tool
//! discovery or downloading. It defines the auditable boundary that a later
//! runner and tool-specific MFTECmd, RECmd, or EvtxECmd importer must satisfy.

mod contract;
mod manifest;
mod runner;

pub use contract::{
    AdapterDescriptor, AdapterSourceCoordinate, AdapterSourceObject, CoordinateQuality, Detection,
    ExecutableIdentity, ImportSummary, LockedCommand, NamedCoordinateSystem, ParserAdapter,
    SecretSafeConfiguration, SemanticArtifactSink, StagedInput, StagedInputs, ToolLock,
};
pub use manifest::{
    AdapterCoverage, AdapterCoverageStatus, BoundedRunOutcome, ParserRunManifest, RunLimitKind,
    RunLimits, RunTermination, TerminationCapability, PARSER_RUN_MANIFEST_SCHEMA_VERSION,
};
pub use runner::{
    execute_locked_parser, prepare_run_directory, stage_input_copy, verify_tool_installation,
    CancellationToken, CapturedStream, ParserRunExecution, PreparedRunDirectory,
    RunDirectoryPrivacy, RunnerRequest, StageFileRequest, VerifiedToolInstallation,
};
