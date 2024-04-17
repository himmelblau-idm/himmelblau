use uuid::Uuid;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum IdmapError {
    IDMAP_NOT_IMPLEMENTED,
    IDMAP_ERROR,
    IDMAP_SID_INVALID,
    IDMAP_NO_RANGE,
    IDMAP_COLLISION,
}

#[allow(dead_code)]
struct AadSid {
    sid_rev_num: u8,
    num_auths: i8,
    id_auth: u64, // Technically only 48 bits
    sub_auths: [u32; 15],
}

fn object_id_to_sid(object_id: &Uuid) -> Result<AadSid, IdmapError> {
    let bytes_array = object_id.as_bytes();
    let s_bytes_array = [
        bytes_array[6],
        bytes_array[7],
        bytes_array[4],
        bytes_array[5],
    ];

    let mut sid = AadSid {
        sid_rev_num: 1,
        num_auths: 5,
        id_auth: 12,
        sub_auths: [0; 15],
    };

    sid.sub_auths[0] = 1;
    sid.sub_auths[1] = u32::from_be_bytes(
        bytes_array[0..4]
            .try_into()
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );
    sid.sub_auths[2] = u32::from_be_bytes(s_bytes_array);
    sid.sub_auths[3] = u32::from_le_bytes(
        bytes_array[8..12]
            .try_into()
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );
    sid.sub_auths[4] = u32::from_le_bytes(
        bytes_array[12..]
            .try_into()
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );

    Ok(sid)
}

fn rid_from_sid(sid: &AadSid) -> Result<u32, IdmapError> {
    Ok(sid.sub_auths
        [usize::try_from(sid.num_auths).map_err(|_| IdmapError::IDMAP_SID_INVALID)? - 1])
}

pub(crate) fn object_id_to_unix_id(
    object_id: &Uuid,
    idmap_range: (u32, u32),
) -> Result<u32, IdmapError> {
    let sid = object_id_to_sid(object_id)?;
    let rid = rid_from_sid(&sid)?;
    if idmap_range.0 >= idmap_range.1 {
        return Err(IdmapError::IDMAP_NO_RANGE);
    }
    let uid_count = idmap_range.1 - idmap_range.0;
    Ok((rid % uid_count) + idmap_range.0)
}
