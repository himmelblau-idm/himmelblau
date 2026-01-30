// SPDX-FileCopyrightText: 2025 David Mulder <dmulder@suse.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Embedded WebKit browser widget for DAG (Device Authorization Grant) authentication.
//!
//! This widget displays an embedded browser for browser-based authentication flows,
//! along with the device code for the user to enter.

use gtk4::prelude::*;
use gtk4::{gdk, Align, Orientation};
use relm4::prelude::*;
use webkit6::prelude::WebViewExt;
use webkit6::WebView;

use crate::dag::DagInfo;

/// Configuration for the DAG browser widget.
#[derive(Debug, Clone)]
pub struct DagBrowserConfig {
    /// Width of the browser widget.
    pub width: i32,
    /// Height of the browser widget.
    pub height: i32,
}

impl Default for DagBrowserConfig {
    fn default() -> Self {
        Self {
            width: 500,
            height: 600,
        }
    }
}

/// Initialization data for the DAG browser.
#[derive(Debug, Clone)]
pub struct DagBrowserInit {
    /// The DAG information (URL and optional code).
    pub dag_info: DagInfo,
    /// Configuration for the browser widget.
    pub config: DagBrowserConfig,
}

/// The DAG browser component model.
#[derive(Debug)]
pub struct DagBrowser {
    /// The WebKit WebView widget.
    web_view: WebView,
    /// The device code to display.
    device_code: Option<String>,
    /// Whether the code was copied to clipboard.
    code_copied: bool,
}

/// Input messages for the DAG browser.
#[derive(Debug)]
pub enum DagBrowserInput {
    /// Navigate to a new URL.
    Navigate(String),
    /// Update the device code display.
    SetDeviceCode(Option<String>),
    /// Copy the device code to clipboard.
    CopyCode,
    /// Hide/close the browser.
    Hide,
}

/// Output messages from the DAG browser.
#[derive(Debug)]
pub enum DagBrowserOutput {
    /// The user requested to close the browser.
    CloseRequested,
}

#[relm4::component(pub)]
impl Component for DagBrowser {
    type Init = DagBrowserInit;
    type Input = DagBrowserInput;
    type Output = DagBrowserOutput;
    type CommandOutput = ();

    view! {
        gtk4::Box {
            set_orientation: Orientation::Vertical,
            set_spacing: 10,
            set_margin_all: 10,
            add_css_class: "dag-browser-container",

            // Device code display section
            gtk4::Box {
                set_orientation: Orientation::Vertical,
                set_spacing: 5,
                set_halign: Align::Center,

                #[name = "code_label"]
                gtk4::Label {
                    add_css_class: "dag-device-code",
                    set_halign: Align::Center,
                    #[watch]
                    set_label: model.device_code.as_deref().unwrap_or(""),
                    #[watch]
                    set_visible: model.device_code.is_some(),
                },

                gtk4::Label {
                    add_css_class: "dag-instruction",
                    set_halign: Align::Center,
                    set_label: "Enter this code in the browser below:",
                    #[watch]
                    set_visible: model.device_code.is_some(),
                },

                #[name = "copy_button"]
                gtk4::Button {
                    #[watch]
                    set_label: if model.code_copied { "Copied!" } else { "Copy Code" },
                    set_halign: Align::Center,
                    add_css_class: "dag-copy-button",
                    #[watch]
                    set_visible: model.device_code.is_some(),
                    connect_clicked => DagBrowserInput::CopyCode,
                },
            },

            // Browser container
            gtk4::Frame {
                add_css_class: "dag-browser-frame",

                #[local_ref]
                web_view_widget -> webkit6::WebView {
                    set_hexpand: true,
                    set_vexpand: true,
                }
            }
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        // Create and configure the WebView
        let web_view = WebView::new();

        // Configure security settings
        if let Some(settings) = WebViewExt::settings(&web_view) {
            // Disable features that could be security risks
            settings.set_allow_file_access_from_file_urls(false);
            settings.set_allow_universal_access_from_file_urls(false);
            settings.set_javascript_can_open_windows_automatically(false);
            settings.set_enable_javascript(true);
            settings.set_enable_developer_extras(false);
            settings.set_enable_smooth_scrolling(true);
        }

        // Set size
        web_view.set_size_request(init.config.width, init.config.height);

        // Navigate to the DAG URL
        web_view.load_uri(&init.dag_info.url);

        let model = Self {
            web_view: web_view.clone(),
            device_code: init.dag_info.code,
            code_copied: false,
        };

        let web_view_widget = &model.web_view;
        let widgets = view_output!();

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>, _root: &Self::Root) {
        match msg {
            DagBrowserInput::Navigate(url) => {
                self.web_view.load_uri(&url);
            }
            DagBrowserInput::SetDeviceCode(code) => {
                self.device_code = code;
                self.code_copied = false;
            }
            DagBrowserInput::CopyCode => {
                if let Some(code) = &self.device_code {
                    // Copy to clipboard using GDK
                    if let Some(display) = gdk::Display::default() {
                        let clipboard = display.clipboard();
                        clipboard.set_text(code);
                    }
                    self.code_copied = true;
                }
            }
            DagBrowserInput::Hide => {
                sender.output(DagBrowserOutput::CloseRequested).ok();
            }
        }
    }
}
