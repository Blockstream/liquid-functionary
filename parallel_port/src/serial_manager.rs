//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

use crate::config::ParallelPortConfig;
use crate::constants::HSM_NETWORK_MAGIC;
use crate::message::{MessageSource, ParallelPortMessage};
use crate::serial_port_listener::SerialListener;
use anyhow::bail;
use functionary_common::hsm::{Address, Command, Header};
use nix::ioctl_read_bad;
use nix::libc;
use serialport::posix::TTYPort;
use serialport::{DataBits, FlowControl, Parity, SerialPort, SerialPortSettings, StopBits};
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{env, fs, mem, thread};

ioctl_read_bad!(tiocmget, libc::TIOCMGET, libc::c_int);

/// Object to intialize, monitor and send data via a serial port to a remote HSM module.
pub struct SerialPortManager<'a> {
    path: &'a Path,
    port_settings: SerialPortSettings,
    port: Option<TTYPort>,
    message_bus_tx: SyncSender<MessageSource<ParallelPortMessage>>,
    remote_hsm_message_version: Arc<AtomicU8>,
    serial_write_timeout: Duration,
    listener_join_handle: Option<JoinHandle<()>>,
    ring_indicator_monitor_join_handle: Option<JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl<'a> SerialPortManager<'a> {
    pub fn new(
        path_str: &'a str,
        config: &ParallelPortConfig,
        message_bus_tx: SyncSender<MessageSource<ParallelPortMessage>>,
    ) -> Result<Self, anyhow::Error> {
        let path = Path::new(path_str);
        let port_settings = SerialPortSettings {
            baud_rate: config.serial_port_baud,
            data_bits: DataBits::Eight,
            flow_control: FlowControl::None,
            parity: Parity::None,
            stop_bits: StopBits::One,
            timeout: config.serial_read_timeout,
        };
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let remote_hsm_message_version = Arc::new(AtomicU8::new(0u8));

        Ok(Self {
            path,
            port_settings,
            port: None,
            message_bus_tx,
            remote_hsm_message_version,
            serial_write_timeout: config.serial_write_timeout,
            listener_join_handle: None,
            ring_indicator_monitor_join_handle: None,
            shutdown_flag,
        })
    }

    pub fn open(&mut self) -> Result<(), anyhow::Error> {
        log!(Info, "Opening serial port {:?}", self.path);
        if self.port.is_some() || self.listener_join_handle.is_some() {
            bail!("Serial port is already open");
        }

        log!(Info, "Serial port path: {}", self.path.to_str().unwrap());

        let mut port = TTYPort::open(self.path, &self.port_settings)?;
        port.set_exclusive(false)?;

        let serial_port_listener = SerialListener::new(
            port.try_clone().expect("Failed to clone serial port handle"),
            self.message_bus_tx.clone(),
            self.remote_hsm_message_version.clone(),
            self.shutdown_flag.clone(),
        );
        let listener_join_handle = thread::Builder::new()
            .name("serial port listener".to_string())
            .spawn(move || serial_port_listener.run())
            .expect("Couldn't spawn thread");

        let fd = port.as_raw_fd();
        let shutdown_signal_clone = self.shutdown_flag.clone();

        let script_run_command = match env::var("PARALLEL_PORT_SCRIPT_RUN_COMMAND") {
            Ok(c) => c,
            Err(_) => "/usr/bin/sudo".to_string(),
        };

        let script_path = match env::var("PARALLEL_PORT_SCRIPT_PATH") {
            Ok(c) => c,
            Err(_) => "/usr/bin/button-is-pressed.sh".to_string(),
        };

        let ring_indicator_monitor_join_handle = thread::Builder::new()
            .name("ring indicator monitor".to_string())
            .spawn(move || {
                ring_indicator_monitor(fd, shutdown_signal_clone, script_run_command, script_path)
            })
            .expect("Couldn't spawn thread");

        self.port = Some(port);
        self.listener_join_handle = Some(listener_join_handle);
        self.ring_indicator_monitor_join_handle = Some(ring_indicator_monitor_join_handle);

        Ok(())
    }

    /// Get the currently detected remote HSM version
    pub fn get_remote_hsm_message_version(&self) -> u8 {
        self.remote_hsm_message_version.load(Ordering::SeqCst)
    }

    /// Attempt to send a message along the serial port
    pub fn write_message(&mut self, message: ParallelPortMessage) -> Result<(), anyhow::Error> {
        log!(
            Debug,
            "Sending message (Command {:#04x}, Address: {}, Return Address: {}) on serial port",
            message.header.command as u8,
            message.header.address as u8,
            message.header.return_address as u8
        );

        if self.port.is_none() {
            bail!("Serial port is not open for writing");
        }

        let mut write_buffer = Vec::with_capacity(HSM_NETWORK_MAGIC.len() + message.len());

        let mut header_serialized = message.header.serialize();

        // We are embedding the Sequence Number into the return address of messages being sent across
        // the serial connection to the HSM.
        if let Some(sequence_number) = message.sequence_number {
            if header_serialized[2] & 0xf0 == 0 {
                header_serialized[2] |= sequence_number << 4;
            }
        }

        write_buffer.extend(HSM_NETWORK_MAGIC.clone().as_bytes().iter());
        write_buffer.extend(header_serialized.iter());
        write_buffer.extend(message.payload.iter());

        let mut bytes_written = 0;
        let start_time = Instant::now();

        loop {
            match self.port.as_mut() {
                None => bail!("Serial port is not open for writing"),
                Some(port) => {
                    bytes_written += port.write(write_buffer.as_slice())?;
                    if bytes_written >= write_buffer.len() {
                        break;
                    }
                    write_buffer.drain(..bytes_written);
                    if start_time.elapsed() > self.serial_write_timeout {
                        log!(Warn, "Serial send attempt has timed out, giving up");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn send_empty_message(
        &mut self,
        address: Address,
        return_address: Address,
        command: Command,
        version: u8,
    ) -> Result<(), anyhow::Error> {
        if self.port.is_none() {
            bail!("Serial port is not open for writing");
        }

        let header = Header::for_data(version, address, return_address, command, &[]);
        let message = ParallelPortMessage::new(header, vec![]);
        log!(Debug, "Sending empty message (Command {:#04x}, Address: {}, Return Address: {}) on serial port", command as u8, address as u8, return_address as u8);

        self.write_message(message)?;
        Ok(())
    }

    /// When we want to cycle the serial port tell the listener thread to end, wait for it to end and then
    /// consume self.
    pub fn shutdown(&mut self) -> Result<(), anyhow::Error> {
        if self.port.is_none() {
            bail!("Serial port is not open to be shutdown");
        }
        self.shutdown_flag.store(true, Ordering::SeqCst);

        log!(Debug, "Waiting for Serial Port listener to close");
        let listener_join_handle =
            self.listener_join_handle.take().expect("Listener join handle should be available");
        listener_join_handle.join().map_err(|e| {
            anyhow::Error::msg("Couldn't join on serial listener thread")
                .context(format!("{:?}", e))
        })?;
        let ring_indicator_monitor_join_handle = self
            .ring_indicator_monitor_join_handle
            .take()
            .expect("Ring Indicator monitor join handle should be available");
        ring_indicator_monitor_join_handle.join().map_err(|e| {
            anyhow::Error::msg("Couldn't join on ring indicator monitor thread")
                .context(format!("{:?}", e))
        })?;

        self.shutdown_flag.store(false, Ordering::SeqCst);
        let _ = self.port.take();

        Ok(())
    }

    pub fn cycle(&mut self) -> Result<(), anyhow::Error> {
        log!(Info, "Reinitializing Serial port");
        self.shutdown()?;
        self.open()
    }
}

// Check for button press
// Only process if the serial port can supply the value. SOCAT returns a NOTTY error on this call
fn ring_indicator_monitor(
    fd: RawFd,
    shutdown_flag: Arc<AtomicBool>,
    script_run_command: String,
    script_path: String,
) {
    let mut cts_held = false;
    let mut ipset_updated = Instant::now();
    log!(Debug, "Starting ring indicator monitor");
    loop {
        match check_ring_indicator_bit(fd) {
            Ok(ring_indicator) => {
                if ring_indicator {
                    if !cts_held {
                        cts_held = true;
                        log!(Info, "Detected button press");
                    }
                    if ipset_updated.elapsed() > Duration::from_secs(1) {
                        if fs::metadata(script_path.as_str()).is_ok() {
                            let mut cmd = std::process::Command::new(script_run_command.as_str());
                            cmd.arg(script_path.as_str());
                            if let Err(e) = cmd.output() {
                                log!(Error, "Failed to run command `{} {}`: {:?}", script_run_command, script_path, e);
                            }
                            ipset_updated = Instant::now();
                        } else {
                            log!(Debug, "Script not found at {}", script_path);
                        }
                    }
                } else if cts_held {
                    log!(Info, "Detected button release");
                    cts_held = false;
                }
            }
            Err(e) => {
                log!(Warn, "Problem reading serial port ring indicator: {:?}", e);
                thread::sleep(Duration::from_secs(60));
            }
        }

        if shutdown_flag.load(Ordering::SeqCst) {
            log!(Warn, "Shutting down serial port ring indicator monitor thread");
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn check_ring_indicator_bit(fd: RawFd) -> Result<bool, anyhow::Error> {
    let mut status = mem::MaybeUninit::uninit();
    let result = unsafe {
        tiocmget(fd, status.as_mut_ptr())?;
        status.assume_init()
    };
    Ok(result & libc::TIOCM_RNG > 0)
}
