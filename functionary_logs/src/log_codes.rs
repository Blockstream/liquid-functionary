//{{ Liquid }}
//Copyright (C) {{ 2015,2016,2017,2018 }}  {{ Blockstream }}

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU Affero General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU Affero General Public License for more details.

//You should have received a copy of the GNU Affero General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.


//! # Global table of all log codes
//!

use functionary::*;
use io_log::*;
use rpc::*;

use LegacyUnconvertedLogTrace;
use LegacyUnconvertedLogDebug;
use LegacyUnconvertedLogInfo;
use LegacyUnconvertedLogWarn;
use LegacyUnconvertedLogError;
use LegacyUnconvertedLogFatal;

macro_rules! impl_log(
    ($log_id:expr, $level:ident, $struct:ident $(::$next:ident)*, $desc:expr) => {
        impl_log!($log_id, $level, $struct$(::$next)*, $desc,);
    };
    ($log_id:expr, $level:ident, $struct:ident$(::$next:ident)*, $desc:expr,) => {
        impl $crate::Log for $struct$(::$next)* {
            const SEVERITY: $crate::Severity = $crate::Severity::$level;
            const LOG_ID: &'static str = $log_id;

            fn desc(&self) -> &str {
                $desc
            }
        }
    };
    ($log_id:expr, $level:ident, $struct:ident$(::$next:ident)*<$($lt:tt),*>, $desc:expr) => {
        impl_log!($log_id, $level, $struct$(::$next)*<$($lt),*>, $desc,);
    };
    ($log_id:expr, $level:ident, $struct:ident$(::$next:ident)*<$($lt:tt),*>, $desc:expr,) => {
        impl<$($lt),*> $crate::Log for $struct$(::$next)*<$($lt),*> {
            const SEVERITY: $crate::Severity = $crate::Severity::$level;
            const LOG_ID: &'static str = $log_id;

            fn desc(&self) -> &str {
                $desc
            }
        }
    };
);

impl_log!("F-0000", Info, PeerInfo<'a>, "peer info");
impl_log!("F-0001", Info, SystemInfo<'a>, "system info");
impl_log!("F-1000", Debug, WaitForStage, "wait to start stage");
impl_log!("F-1001", Error, StageOverrun, "overran stage start");
impl_log!("F-1002", Error, StageUnderrun, "underran stage start");
impl_log!("F-1003", Info, PeerStatus<'a>, "the status of a peer");

impl_log!("F-A000", Info, AccountingStatus, "status");

impl_log!("F-A001", Debug, Pegin, "claim pegin");
impl_log!("F-A002", Debug, Pegout<'a>, "request pegout");
impl_log!("F-A003", Debug, Burn, "burn coins");

impl_log!("F-A010", Debug, Donation, "finalize donation");

impl_log!("F-A020", Debug, FinalizeSpend, "finalize spend");
impl_log!("F-A021", Debug, FinalizePegout<'a>, "finalize pegout");
impl_log!("F-A022", Debug, Change, "finalize change");
impl_log!("F-A023", Debug, FinalizeFee, "finalize fee");

impl_log!("F-A900", Fatal, DoublePegin, "double pegin");
impl_log!("F-A910", Warn, DiscrepancyCorrection, "discrepancy correction");
impl_log!("F-A911", Warn, DiscrepancyChanged, "discrepancy changed");
impl_log!("F-A920", Fatal, SpendUnknownUtxo, "unknown input");
impl_log!("F-A921", Fatal, FinalizeUnknownOutput, "unknown output");
impl_log!("F-A998", Fatal, ExcessBurn, "excess burn");
impl_log!("F-A999", Fatal, ExcessPegout, "excess pegout");

impl_log!("F-F100", Info, NewFeeEstimate, "feerate estimate");
impl_log!("F-F101", Warn, FeeEstimateFailed, "fail to get feerate estimate");
impl_log!("F-F102", Info, FeePoolStatus, "fee pool status");
impl_log!("F-F200", Debug, DockFees, "dock fees");
impl_log!("F-F201", Debug, ReclaimFees, "reclaim fees");
impl_log!("F-F202", Debug, Confirm, "confirm tx");
impl_log!("F-F203", Debug, AddFees, "add fees");

impl_log!("F-N100", Debug, ReceiveForSelf, "receive msg (self)");
impl_log!("F-N101", Trace, ReceiveForRelay, "receive msg (relay)");
impl_log!("F-N102", Info, PeerHandshake, "peer version handshake");
impl_log!("F-N103", Info, ProtocolVersion, "our protocol version");
impl_log!("F-N104", Warn, QueuedMessagesCleared, "per-thread messages cleared");
impl_log!("F-N105", Warn, MessageDropped<'a>, "dropped a message");
impl_log!("F-N106", Info, MessageSent, "sent a message");
impl_log!("F-N107", Info, MessageReceived, "received a message");
impl_log!("F-N108", Error, ReceivedStatusAck, "received StatusAck after broadcast rollout");
impl_log!("F-N109", Debug, KickWatchdogForStatusAck, "kicked watchdog due to StatusAck");
impl_log!("F-N110", Debug, KickWatchdogForInStatusAck, "kicked watchdog due to In-Status Ack");

impl_log!("F-P100", Info, RecordRequest<'a>, "record request");
impl_log!("F-P101", Info, ForgetRequest<'a>, "forget request");
impl_log!("F-P110", Info, RequestBadGenesis<'a>, "malformed request (bad genesis)");

impl_log!("F-T001", Debug, RecordTx, "record tx");
impl_log!("F-T002", Debug, RecordTxChange, "change record tx");
impl_log!("F-T003", Info, FinalizeTx, "finalize tx");
impl_log!("F-T004", Debug, DropTx, "drop tx");
impl_log!("F-T005", Info, UndoBlock<'a>, "undo block");
impl_log!("F-T901", Fatal, DeepBitcoinReorg, "fatal reorg");

impl_log!("F-U100", Info, RecordUtxo<'a>, "record utxo");
impl_log!("F-U101", Info, ForgetUtxo, "forget utxo");
impl_log!("F-U102", Fatal, WalletUtxoWithoutDescriptor, "wallet utxo without known descriptor");
impl_log!("F-U103", Warn, DeleteUnspendableUtxo<'a>, "deleting unspendable utxo");
impl_log!("F-U104", Info, FinalizedReclamation, "finalized utxo reclamation");

impl_log!("F-B000", Info, StartingBlocksigner<'a>, "start blocksigner");
impl_log!("F-B100", Info, CombineSignature, "combine sig");
impl_log!("F-B101", Info, WillPropose, "proposing block");

impl_log!("F-B200", Info, Precommit, "precommit");
impl_log!("F-B201", Info, ReceivePrecommit, "receive precommit");
impl_log!("F-B202", Debug, PrecommitDebug<'a>, "precommit (debug)");

impl_log!("F-B400", Info, BlocksignerStartStage, "start stage");
impl_log!("F-B410", Info, BlocksignerRoundComplete, "round complete");
impl_log!("F-B411", Info, BlocksignerRoundSkipped, "round skipped");
impl_log!("F-B413", Error, RoundFailedNoBlock, "round failed (no block proposal)");
impl_log!("F-B414", Error, BlocksignerRoundErrored, "round failed (error)");
impl_log!("F-B415", Error, RoundFailedPrecommits, "round failed (precommits)");
impl_log!("F-B416", Error, RoundFailedSignatures, "round failed (signatures)");
impl_log!("F-B417", Info, BlocksignerSignatureSkipped, "skipped sending signature to peer");
impl_log!("F-B418", Info, BlocksignerConsensusProposal<'a>, "the federation consensus parameters might change");
impl_log!("F-B419", Info, BlocksignerConsensusChanged<'a>, "the federation consensus parameters changed");
impl_log!("F-B420", Error, BlockReplacedInChain, "our block was replaced");
impl_log!("F-B421", Info, ConsensusManagementState, "federation consensus-management information");

impl_log!("F-B500", Error, BlockFromNonMaster, "block from non-master");
impl_log!("F-B501", Error, BlockAtWrongTime, "unexpected block from master");
impl_log!("F-B502", Error, HsmRejectBlock<'a>, "hsm rejected block");
impl_log!("F-B503", Error, DaemonRejectBlock<'a>, "daemon rejected block");
impl_log!("F-B504", Error, PrecommitAtWrongTime, "precommit at wrong time");
impl_log!("F-B505", Error, PrecommitWrongHash, "precommit to wrong block");

impl_log!("F-D001", Error, PrematureProposal, "premature proposal");

impl_log!("F-D010", Warn, PeerCountMismatch, "peer count mismatch");
impl_log!("F-D011", Warn, PeerUnknownPeer, "unknown peer");
impl_log!("F-D012", Warn, PeerCommKeyMismatch, "peer comm key mismatch");
impl_log!("F-D013", Error, PeerSignKeyMismatch, "peer sign key mismatch");
impl_log!("F-D014", Warn, UnknownDynafedParamsSignalled, "unknown dynafed params");
impl_log!("F-D015", Info, ProposingParams, "proposing new params");
impl_log!("F-D016", Info, ConsensusParameterTally<'a>, "potential CPE");
impl_log!("F-D017", Info, ConsensusParameterParsed<'a>, "CPE from config file");

impl_log!("F-D020", Fatal, UnknownParamsActivated, "unknown dynafed params activated");
impl_log!("F-D021", Error, UnknownActiveCpe, "unknown active cpe in proposal");
impl_log!("F-D022", Error, UnknownProposedCpe, "unknown proposed cpe");
impl_log!("F-D023", Debug, ProposalDynafedActivationSignal<'a>, "dynafed signalling");
impl_log!("F-D024", Error, OldCpeProposed, "old cpe proposed");
impl_log!("F-D025", Error, CpeProposedEarly, "cpe proposed prematurely");
impl_log!("F-D026", Fatal, ExpectedDynafedHeader, "expected dynafed block header extdata");
impl_log!("F-D027", Error, CpeCommitmentsMismatch, "descriptor commitments do not match proposed CPE");
impl_log!("F-D028", Info, ParamsUpdated, "cpe statuses updated");
impl_log!("F-D029", Warn, BlockNoCommitments, "block did not contain descriptor commitments");
impl_log!("F-D030", Info, BlockIncludesDescriptors, "block contains descriptors");
impl_log!("F-D031", Warn, PeerStatusMismatch<'a>, "problem integrating peer status");


impl_log!("F-W000", Info, StartingWatchman<'a>, "start watchman");
impl_log!("F-W001", Info, NoCacheFile<'a>, "no cache, rescanning");
impl_log!("F-W002", Error, DescriptorChanged<'a>, "descriptor changed, rescanning");
impl_log!("F-W003", Error, MainConfsChanged<'a>, "mainchain conf depth changed, rescanning");
impl_log!("F-W004", Error, SideConfsChanged<'a>, "sidechain conf depth changed, rescanning");
impl_log!("F-W005", Warn, PublicKeyRetrievalFailed, "failed to retrieve public key, retrying");
impl_log!("F-W006", Info, WatchmanStartupStarted, "started watchman startup procedure");
impl_log!("F-W007", Info, WatchmanStartupFinished, "finished watchman startup procedure");
impl_log!("F-W008", Warn, BadDescriptorOrder, "v1-style descriptor used with bad peer ordering");
impl_log!("F-W009", Error, CorruptCacheFile<'a>, "corrupt cache, rescanning");

impl_log!("F-W010", Info, ChangeAddress, "regular change address");
impl_log!("F-W011", Info, CsvTweakedChangeAddress, "CSV-tweaked change address");

impl_log!("F-W100", Info, WatchmanSyncStatus<'a>, "sync chain");
impl_log!("F-W101", Info, SaveCacheFile<'a>, "serialize cache to disk");
impl_log!("F-W102", Info, WalletSummary<'a>, "wallet summary");
impl_log!("F-W103", Info, MempoolCacheStatus, "mempool cache status");

impl_log!("F-W200", Info, StartTxProposal<'a>, "start tx proposal");
impl_log!("F-W201", Debug, IgnoreUneconomicalUtxo, "ignore utxo");
impl_log!("F-W202", Warn, UtxoNearExpiry, "utxo near expiry");
impl_log!("F-W203", Info, NotSpendingUtxo, "not spending utxo");
impl_log!("F-W204", Info, IgnoringPegout, "ignoring pegout");
impl_log!("F-W205", Info, IgnoringPegoutHsmFull, "hsm full");
impl_log!("F-W206", Warn, IgnoringPegoutBadPak, "bad pak proof");
impl_log!("F-W207", Debug, EmptyProposal, "empty proposal");
//impl_log!("F-W208", Error, FailedProposal, "failed proposal");
impl_log!("F-W209", Debug, IncludingPegout, "include pegout");
impl_log!("F-W210", Debug, CreatedUnsignedTx, "created unsigned tx");
impl_log!("F-W211", Info, SigningTx, "signing tx");
impl_log!("F-W212", Error, RefusedProposal<'a>, "refused proposal");
impl_log!("F-W213", Info, ReceivedTxPrecommit, "receive tx precommit");
impl_log!("F-W214", Warn, PrecommitWrongTxid, "precommit to wrong txid");
impl_log!("F-W215", Warn, DetectedLegacyChange<'a>, "detected new change with a legacy script");
impl_log!("F-W216", Warn, DetectedLegacyDonation<'a>, "detected donation to legacy script");
impl_log!("F-W217", Info, ExplicitlySweepUtxo, "explicitly sweep utxo");
impl_log!("F-W218", Info, AddedFailedPegin, "manually added failed pegin to be swept");
impl_log!("F-W219", Warn, CantSignFailedPeginReclamation<'a>, "available signers cannot sign failed pegin reclamation");
impl_log!("F-W220", Error, FailedPeginNotMature, "failed pegin is not mature yet");
impl_log!("F-W221", Info, FailedPeginNotInUtxoSet, "cannot find failed pegin in UTXO set");
impl_log!("F-W222", Error, FailedPeginCanBeClaimed, "pegin can be claimed");
impl_log!("F-W223", Info, LoadedFailedPegin, "pegin loaded from config");
impl_log!("F-W224", Info, ReclaimFailedPegin, "reclaim failed pegin utxo");
impl_log!("F-W225", Info, FailedPeginReclamationInMempool, "failed pegin reclamation in mempool");
impl_log!("F-W298", Info, ValidateProposal<'a>, "validate tx proposal");
impl_log!("F-W299", Info, CompleteProposal<'a>, "complete tx proposal");

impl_log!("F-W300", Debug, UpdateConflictRequirements<'a>, "require conflicts");
impl_log!("F-W301", Debug, ClearConflictRequirements, "clear conflicts");
impl_log!("F-W302", Warn, UnconfirmedDoubleSpend<'a>, "double spend");
impl_log!("F-W303", Warn, PegoutToFederation, "pegout to federation");

impl_log!("F-W400", Info, WatchmanStartStage, "start stage");
impl_log!("F-W400", Info, WatchmanProductiveRound, "start stage");
impl_log!("F-W410", Info, WatchmanRoundComplete<'a>, "round complete");
impl_log!("F-W411", Info, WatchmanRoundSkipped, "round skipped");
impl_log!("F-W412", Info, WatchmanRoundIdled, "round idled");
impl_log!("F-W413", Warn, WatchmanRoundFailed, "round failed");
impl_log!("F-W414", Error, WatchmanRoundErrored, "round failed (error)");
impl_log!("F-W415", Info, WatchmanConsensusChanged<'a>, "the federation consensus parameters changed");
impl_log!("F-W416", Info, TotalPrunedUtxos, "total number of pruned utxos this round");

impl_log!("F-W500", Error, ProposalFromNonMaster, "proposal from non-master");
impl_log!("F-W501", Error, IdleFromNonMaster, "idle from non-master");
// deprecated commands
// impl_log!("F-W502", Error, NackFromMaster, "master NAK'd: sitting out this round");
// impl_log!("F-W503", Warn, NackFromPeer, "peer NAK'd: dropping them from round");
// impl_log!("F-W504", Warn, NackUnexpected, "peer NAK'd when neither of us are master");

impl_log!("F-W600", Debug, HsmSendingHeader, "sending block header to HSM");
impl_log!("F-W601", Debug, HsmAcceptedHeader, "HSM accepted new header");
impl_log!("F-W602", Error, HsmRefusedHeader, "HSM refused header");
impl_log!("F-W603", Error, HsmErrorOnHeader, "HSM errored while processing header header");

impl_log!("F-W800", Warn, RpcSyncFailed, "RPC sync failed");
impl_log!("F-W801", Warn, TxUnknownAfterBroadcast, "tx unknown after broadcast");
impl_log!("F-W802", Info, CombineSigs<'a>, "combining signatures");

impl_log!("F-W900", Fatal, DetectedUnknownOutput<'a>, "detected unknown output");
impl_log!("F-W901", Fatal, DetectedUnknownInputs, "detected unknown inputs");
impl_log!("F-W902", Fatal, NoSuchBlock, "Bitcoin block not found");
impl_log!("F-W903", Error, WatchmanBlockCheckError, "appropriate block not found");

impl_log!("F-W910", Debug, MainchainCommitmentFound, "mainchain commitment found");
impl_log!("F-W911", Debug, MainchainCommitmentUpdated, "mainchain commitment updated");
impl_log!("F-W912", Warn, MainchainCommitmentForked, "mainchain commitment forked");
impl_log!("F-W913", Warn, MainchainCommitmentBackwards, "mainchain commitment went backwards");
impl_log!("F-W914", Warn, MainchainCommitmentUnknown, "mainchain commitment unknown");

impl_log!("F-IO80", Warn, ReadFailed<'a>, "read failed");
impl_log!("F-IO81", Warn, WriteFailed<'a>, "write failed");
impl_log!("F-IO82", Warn, CreateFailed<'a>, "create failed");
impl_log!("F-IO83", Warn, MoveFailed<'a>, "move/rename failed");

impl_log!("F-R001", Info, WarmingUp<'a>, "warming up");
impl_log!("F-R002", Info, WarmedUp<'a>, "warmed up");
impl_log!("F-R003", Trace, RpcRequest<'a>, "RPC request");
impl_log!("F-R004", Debug, RpcResponse<'a>, "RPC response");
impl_log!("F-R005", Trace, RpcResultTrace<'a>, "result portion of RPC response");
impl_log!("F-R800", Warn, UnexpectedRpcResponse<'a>, "unexpected RPC response");
impl_log!("F-R900", Error, Error<'a, 'b>, "rpc error");


impl_log!("F-L000", Trace, LegacyUnconvertedLogTrace, "legacy log");
impl_log!("F-L001", Debug, LegacyUnconvertedLogDebug, "legacy log");
impl_log!("F-L002", Info, LegacyUnconvertedLogInfo, "legacy log");
impl_log!("F-L003", Warn, LegacyUnconvertedLogWarn, "legacy log");
impl_log!("F-L004", Error, LegacyUnconvertedLogError, "legacy log");
impl_log!("F-L005", Fatal, LegacyUnconvertedLogFatal, "legacy log");
