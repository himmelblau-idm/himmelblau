/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HomeAttr {
    Uuid,
    Spn,
    Cn,
    Name,
}

impl Display for HomeAttr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HomeAttr::Uuid => "UUID",
                HomeAttr::Spn => "SPN",
                HomeAttr::Cn => "CN",
                HomeAttr::Name => "Name",
            }
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub enum UidAttr {
    Name,
    Spn,
}

impl Display for UidAttr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                UidAttr::Name => "Name",
                UidAttr::Spn => "SPN",
            }
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum HsmType {
    #[default]
    Soft,
    TpmIfPossible,
    Tpm,
}

impl Display for HsmType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmType::Soft => write!(f, "Soft"),
            HsmType::TpmIfPossible => write!(f, "Tpm if possible"),
            HsmType::Tpm => write!(f, "Tpm"),
        }
    }
}
