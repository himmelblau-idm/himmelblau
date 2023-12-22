use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone)]
pub enum HomeAttr {
    Uuid,
    Spn,
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

#[derive(Debug, Clone, Default)]
pub enum HsmType {
    #[cfg_attr(not(feature = "tpm"), default)]
    Soft,
    #[cfg_attr(feature = "tpm", default)]
    Tpm,
}
