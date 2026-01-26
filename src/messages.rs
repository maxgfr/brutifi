/*!
 * Application messages
 *
 * Defines all messages that can be sent in the application.
 */

use std::path::PathBuf;

use crate::screens::{CrackEngine, CrackMethod, Wpa3AttackMethod, WpsAttackMethod};
use crate::workers::{CaptureProgress, CrackProgress, ScanResult};

/// Application messages
#[derive(Debug, Clone)]
pub enum Message {
    // Navigation
    GoToScanCapture,
    GoToCrack,
    GoToWps,
    GoToWpa3,

    // Scan & Capture screen
    StartScan,
    StopScan,
    ResetScanState,
    ScanComplete(ScanResult),
    SelectNetwork(usize),
    SelectChannel(String),
    InterfaceSelected(String),
    BrowseCaptureFile,
    CaptureFileSelected(Option<PathBuf>),
    DownloadCapturedPcap,
    SaveCapturedPcap(Option<PathBuf>),
    DisconnectWifi,
    WifiDisconnectResult(Result<(), String>),
    StartCapture,
    StopCapture,
    CaptureProgress(CaptureProgress),
    #[allow(dead_code)]
    EnableAdminMode,

    // Crack screen
    HandshakePathChanged(String),
    EngineChanged(CrackEngine),
    MethodChanged(CrackMethod),
    MinDigitsChanged(String),
    MaxDigitsChanged(String),
    WordlistPathChanged(String),
    BrowseHandshake,
    BrowseWordlist,
    HandshakeSelected(Option<PathBuf>),
    WordlistSelected(Option<PathBuf>),
    StartCrack,
    StopCrack,
    CrackProgress(CrackProgress),
    CopyPassword,
    #[allow(dead_code)]
    ReturnToNormalMode,

    // WPS Attack screen
    WpsMethodChanged(WpsAttackMethod),
    WpsBssidChanged(String),
    WpsChannelChanged(String),
    WpsInterfaceChanged(String),
    WpsCustomPinChanged(String),
    StartWpsAttack,
    StopWpsAttack,
    WpsProgress(brutifi::WpsProgress),

    // WPA3 Attack screen
    Wpa3MethodChanged(Wpa3AttackMethod),
    Wpa3BssidChanged(String),
    Wpa3ChannelChanged(String),
    Wpa3InterfaceChanged(String),
    StartWpa3Attack,
    StopWpa3Attack,
    Wpa3Progress(brutifi::Wpa3Progress),

    // General
    Tick,
}
