// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod tests {
    #[test]
    fn encoding() {
        let soc_id = "0x00112233445566778899aabb00000000";
        let soc_id = hex::decode(soc_id.strip_prefix("0x").unwrap()).unwrap();
        let soc_id = u128::from_be_bytes(soc_id.as_slice().try_into().unwrap());
        let mut id = [0x0u8; 16];
        id.copy_from_slice(soc_id.to_le_bytes().as_ref());

        println!("{:032x}", soc_id);
        println!("{:x?}", id);

        let permissions_mask = "0x0000000000000000FFFFFFFF00000000";
        let permissions_mask = hex::decode(permissions_mask.strip_prefix("0x").unwrap()).unwrap();
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        let mut permissions = [0x0u8; 16];
        permissions.copy_from_slice(permissions_mask.to_le_bytes().as_ref());

        println!("{:032x}", permissions_mask);
        println!("{:x?}", permissions);

        let permissions_mask = "0x8000000000000000FFFFFFFF00000000";
        let permissions_mask = hex::decode(permissions_mask.strip_prefix("0x").unwrap()).unwrap();
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        let mut permissions = [0x0u8; 16];
        permissions.copy_from_slice(permissions_mask.to_le_bytes().as_ref());

        println!("{:032x}", permissions_mask);
        println!("{:x?}", permissions);
    }
}
