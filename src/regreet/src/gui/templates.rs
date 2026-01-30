// SPDX-FileCopyrightText: 2022 Harish Rajagopal <harish.rajagopals@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Templates for various GUI components
#![allow(dead_code)] // Silence dead code warnings for UI code that isn't dead

use gtk::prelude::*;
use relm4::{gtk, RelmWidgetExt, WidgetTemplate};

/// Button that ends the greeter (eg. Reboot)
#[relm4::widget_template(pub)]
impl WidgetTemplate for EndButton {
    view! {
        gtk::Button {
            set_focusable: true,
            add_css_class: "destructive-action",
        }
    }
}

/// Label for an entry/combo box
#[relm4::widget_template(pub)]
impl WidgetTemplate for EntryLabel {
    view! {
        gtk::Label {
            set_width_request: 100,
            set_xalign: 1.0,
        }
    }
}

/// Main UI of the greeter
#[relm4::widget_template(pub)]
impl WidgetTemplate for Ui {
    view! {
        gtk::Overlay {
            /// Background image
            #[name = "background"]
            gtk::Picture,

            /// Main login box
            add_overlay = &gtk::Frame {
                set_halign: gtk::Align::Center,
                set_valign: gtk::Align::Center,
                add_css_class: "background",

                gtk::Grid {
                    set_column_spacing: 15,
                    set_margin_bottom: 15,
                    set_margin_end: 15,
                    set_margin_start: 15,
                    set_margin_top: 15,
                    set_row_spacing: 15,
                    set_width_request: 500,

                    /// Widget to display messages to the user
                    #[name = "message_label"]
                    attach[0, 0, 3, 1] = &gtk::Label {
                        set_margin_bottom: 15,

                        // Format all messages in boldface.
                        #[wrap(Some)]
                        set_attributes = &gtk::pango::AttrList {
                            insert: {
                                let mut font_desc = gtk::pango::FontDescription::new();
                                font_desc.set_weight(gtk::pango::Weight::Bold);
                                gtk::pango::AttrFontDesc::new(&font_desc)
                            },
                        },
                    },

                    #[template]
                    attach[0, 1, 1, 1] = &EntryLabel {
                        set_label: "User:",
                        set_height_request: 45,
                    },

                    /// Label for the sessions widget
                    #[name = "session_label"]
                    #[template]
                    attach[0, 2, 1, 1] = &EntryLabel {
                        set_label: "Session:",
                        set_height_request: 45,
                    },

                    /// Widget containing the usernames
                    #[name = "usernames_box"]
                    attach[1, 1, 1, 1] = &gtk::ComboBoxText { set_hexpand: true },

                    /// Widget where the user enters the username
                    #[name = "username_entry"]
                    attach[1, 1, 1, 1] = &gtk::Entry { set_hexpand: true },

                    /// Widget containing the sessions
                    #[name = "sessions_box"]
                    attach[1, 2, 1, 1] = &gtk::ComboBoxText,

                    /// Widget where the user enters the session
                    #[name = "session_entry"]
                    attach[1, 2, 1, 1] = &gtk::Entry,

                    /// Label for the password widget
                    #[name = "input_label"]
                    #[template]
                    attach[0, 2, 1, 1] = &EntryLabel {
                        set_height_request: 45,
                    },

                    /// Widget where the user enters a secret
                    #[name = "secret_entry"]
                    attach[1, 2, 1, 1] = &gtk::PasswordEntry { set_show_peek_icon: true },

                    /// Widget where the user enters something visible
                    #[name = "visible_entry"]
                    attach[1, 2, 1, 1] = &gtk::Entry,

                    /// Buttons for username: copy and toggle manual entry
                    attach[2, 1, 1, 1] = &gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 5,

                        #[name = "user_copy"]
                        gtk::Button {
                            set_icon_name: "edit-copy-symbolic",
                            set_tooltip_text: Some("Copy username to clipboard"),
                        },

                        #[name = "user_toggle"]
                        gtk::ToggleButton {
                            set_icon_name: "document-edit-symbolic",
                            set_tooltip_text: Some("Manually enter username"),
                        },
                    },

                    /// Button to toggle manual session entry
                    #[name = "sess_toggle"]
                    attach[2, 2, 1, 1] = &gtk::ToggleButton {
                        set_icon_name: "document-edit-symbolic",
                        set_tooltip_text: Some("Manually enter session command"),
                    },

                    /// Collection of action buttons (eg. Login)
                    attach[1, 3, 2, 1] = &gtk::Box {
                        set_halign: gtk::Align::End,
                        set_spacing: 15,

                        /// Button to cancel password entry
                        #[name = "cancel_button"]
                        gtk::Button {
                            set_focusable: true,
                            set_label: "Cancel",
                        },

                        /// Button to enter the password and login
                        #[name = "login_button"]
                        gtk::Button {
                            set_focusable: true,
                            set_label: "Login",
                            set_receives_default: true,
                            add_css_class: "suggested-action",
                        },
                    },
                },
            },

            /// Clock widget
            #[name = "clock_frame"]
            add_overlay = &gtk::Frame {
                set_halign: gtk::Align::Center,
                set_valign: gtk::Align::Start,

                add_css_class: "background",

                // Make it fit cleanly onto the top edge of the screen.
                inline_css: "
                    border-top-right-radius: 0px;
                    border-top-left-radius: 0px;
                    border-top-width: 0px;
                ",
            },

            /// DAG browser container (for browser-based authentication)
            #[name = "dag_browser_frame"]
            add_overlay = &gtk::Frame {
                set_halign: gtk::Align::Start,
                set_valign: gtk::Align::Center,
                set_margin_start: 50,
                add_css_class: "background",
                set_visible: false,

                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 10,
                    set_margin_all: 15,

                    /// Device code label
                    #[name = "dag_code_label"]
                    gtk::Label {
                        add_css_class: "dag-device-code",
                        set_halign: gtk::Align::Center,

                        // Large, bold text for the device code
                        #[wrap(Some)]
                        set_attributes = &gtk::pango::AttrList {
                            insert: {
                                let mut font_desc = gtk::pango::FontDescription::new();
                                font_desc.set_weight(gtk::pango::Weight::Bold);
                                font_desc.set_size(24 * gtk::pango::SCALE);
                                gtk::pango::AttrFontDesc::new(&font_desc)
                            },
                        },
                    },

                    gtk::Label {
                        set_label: "Enter this code in the browser below:",
                        set_halign: gtk::Align::Center,
                    },

                    /// Copy code button
                    #[name = "dag_copy_button"]
                    gtk::Button {
                        set_label: "Copy Code",
                        set_halign: gtk::Align::Center,
                    },

                    /// Browser placeholder - the actual WebView is added dynamically
                    #[name = "dag_browser_box"]
                    gtk::Box {
                        set_size_request: (500, 500),
                        set_hexpand: true,
                        set_vexpand: true,
                    },
                },
            },

            /// Collection of widgets appearing at the bottom
            add_overlay = &gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_halign: gtk::Align::Center,
                set_valign: gtk::Align::End,
                set_margin_bottom: 15,
                set_spacing: 15,

                gtk::Frame {
                    /// Notification bar for error messages
                    #[name = "error_info"]
                    gtk::InfoBar {
                        // During init, the info bar closing animation is shown. To hide that, make
                        // it invisible. Later, the code will permanently make it visible, so that
                        // `InfoBar::set_revealed` will work properly with animations.
                        set_visible: false,
                        set_message_type: gtk::MessageType::Error,

                        /// The actual error message
                        #[name = "error_label"]
                        gtk::Label {
                            set_halign: gtk::Align::Center,
                            set_margin_top: 10,
                            set_margin_bottom: 10,
                            set_margin_start: 10,
                            set_margin_end: 10,
                        },
                    }
                },

                /// Collection of buttons that close the greeter (eg. Reboot)
                gtk::Box {
                    set_halign: gtk::Align::Center,
                    set_homogeneous: true,
                    set_spacing: 15,

                    /// Button to reboot
                    #[name = "reboot_button"]
                    #[template]
                    EndButton { set_label: "Reboot" },

                    /// Button to power-off
                    #[name = "poweroff_button"]
                    #[template]
                    EndButton { set_label: "Power Off" },
                },
            },
        }
    }
}
