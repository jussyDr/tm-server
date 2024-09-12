pub fn decompress(src: &[u8], dst: &mut [u8], dict: &[u8]) -> Result<usize, ()> {
    unsafe {
        let src_len = src.len();
        let dst_len = dst.len();
        let dict_len = dict.len();
        let src = src.as_ptr() as *mut u8;
        let dst = dst.as_mut_ptr();
        let dict = dict.as_ptr();

        let src_end = src.byte_add(src_len);
        let dst_end = dst.byte_add(dst_len);
        let dict_end = dict.byte_add(dict_len);

        let mut cur_src;
        let mut next_src;
        let mut cur_dst;
        let mut instr;
        let mut lit_len;
        let mut extra_lit_len: isize;
        let mut next_dst;
        let mut instr_copy;
        let mut instr_2;
        let mut instr_2_copy;
        let mut match_off;
        let mut match_len;
        let mut local_40;
        let mut stack_3f;
        let mut stack_3a;
        let mut stack_39;
        let mut stack_3c;
        let mut stack_3b;
        let mut var_5;
        let mut var_6;
        let mut var_7;
        let mut var_1;
        let mut var_2;
        let mut var_8;

        if dst_len == 0 {
            unimplemented!()
        } else if src_len != 0 {
            cur_src = src;
            next_src = src;
            cur_dst = dst;

            if dst_len < 64 {
                unimplemented!()
            }

            loop {
                instr = *cur_src;
                next_src = cur_src.byte_add(1);
                lit_len = (instr >> 4) as isize;

                if lit_len == 15 {
                    extra_lit_len = 0;

                    if src_end.byte_sub(15) <= next_src {
                        unimplemented!()
                    }

                    loop {
                        let value = *next_src;
                        next_src = next_src.byte_add(1);
                        extra_lit_len += value as isize;

                        if src_end.byte_sub(15) < next_src {
                            unimplemented!()
                        }

                        if value == 255 {
                            continue;
                        } else {
                            break;
                        }
                    }

                    if extra_lit_len == -1 {
                        unimplemented!()
                    }

                    lit_len = extra_lit_len + 15;
                    next_dst = cur_dst.byte_offset(lit_len);

                    if next_dst < cur_dst {
                        unimplemented!()
                    } else {
                        cur_src = next_src.byte_offset(lit_len);

                        if cur_src < next_src {
                            unimplemented!()
                        }
                    }

                    instr_copy = instr as u32;

                    if dst_end.byte_sub(4) < next_dst {
                        //// LAB 400 ////

                        if dst_end.byte_sub(12) < next_dst
                            || src_end.byte_sub(8) < next_src.byte_offset(lit_len)
                        {
                            if next_src.byte_offset(lit_len) == src_end && next_dst <= dst_end {
                                cur_dst.copy_from(next_src, lit_len as usize);

                                return Ok(
                                    ((cur_dst as i32) + ((lit_len as i32) - (dst as i32))) as usize
                                );
                            }

                            unimplemented!()
                        }

                        unimplemented!()
                    }

                    instr_copy = instr as u32;

                    if src_end.byte_sub(32) < cur_src {
                        unimplemented!()
                    }

                    extra_lit_len = (cur_dst as isize) - (next_src as isize);

                    loop {
                        var_1 = next_src.byte_add(32);
                        var_2 = var_1.byte_offset(extra_lit_len - 32);
                        var_2.copy_from(next_src, 32);
                        next_src = var_1;

                        if var_1.byte_offset(extra_lit_len) < next_dst {
                            continue;
                        } else {
                            break;
                        }
                    }
                } else {
                    next_dst = cur_dst.byte_offset(lit_len);
                    instr_copy = instr as u32;

                    if src_end.byte_sub(17) < next_src {
                        unimplemented!()
                    }

                    var_5 = cur_src.byte_add(5);
                    var_6 = cur_src.byte_add(9);
                    var_7 = cur_src.byte_add(13);
                    cur_src = next_src.byte_offset(lit_len);
                    cur_dst.copy_from(next_src, 4);
                    (cur_dst.byte_add(4).copy_from(var_5, 4));
                    (cur_dst.byte_add(8).copy_from(var_6, 4));
                    (cur_dst.byte_add(12).copy_from(var_7, 4));
                }

                instr_2 =
                    u16::from_le_bytes(std::slice::from_raw_parts(cur_src, 2).try_into().unwrap());
                instr_2_copy = instr_2 as usize;
                match_off = next_dst.byte_sub(instr_2_copy);
                next_src = cur_src.byte_add(2);

                if instr & 15 == 15 {
                    extra_lit_len = 0;

                    loop {
                        instr = *next_src;
                        next_src = next_src.byte_add(1);
                        extra_lit_len += instr as isize;

                        if src_end.byte_sub(4) < next_src {
                            unimplemented!()
                        }

                        if instr != 255 {
                            break;
                        }
                    }

                    if extra_lit_len == -1 {
                        unimplemented!()
                    }

                    match_len = extra_lit_len + 19;
                    cur_dst = next_dst.byte_offset(match_len);

                    if cur_dst < next_dst
                        || (dict_len < 0x10000 && match_off.byte_add(dict_len) < dst)
                    {
                        unimplemented!()
                    }

                    if dst_end.byte_sub(8) <= cur_dst {
                        unimplemented!()
                    }
                } else {
                    match_len = ((instr & 15) + 4) as isize;
                    cur_dst = next_dst.byte_offset(match_len);

                    if dst_end.byte_sub(8) <= cur_dst {
                        unimplemented!()
                    }

                    if match_off >= dst && instr_2_copy >= 8 {
                        next_dst.copy_from(match_off, 18);
                        cur_src = next_src;

                        continue;
                    }
                }

                //// LAB 137 ////

                if dict_len < 0x10000 && match_off.byte_add(dict_len) < dst {
                    unimplemented!()
                }

                cur_src = next_src;

                if dst <= match_off {
                    if 15 < instr_2_copy {
                        extra_lit_len = (next_dst as isize) - (match_off as isize);

                        loop {
                            next_dst = match_off;
                            next_dst.byte_offset(extra_lit_len).copy_from(match_off, 32);
                            next_dst = next_dst.byte_add(32);
                            next_src = next_dst.byte_offset(extra_lit_len - 16);
                            match_off = next_dst;

                            if next_dst.offset(extra_lit_len) < cur_dst {
                                continue;
                            } else {
                                break;
                            }
                        }

                        continue;
                    }

                    if instr_2_copy == 1 {
                        unimplemented!()
                    } else if instr_2_copy == 2 {
                        local_40 = (u16::from_le_bytes(
                            std::slice::from_raw_parts(match_off, 2).try_into().unwrap(),
                        ) & 0xff) as u8;
                        stack_3f = (u16::from_le_bytes(
                            std::slice::from_raw_parts(match_off, 2).try_into().unwrap(),
                        ) >> 8) as u8;
                        stack_3a = local_40;
                        stack_39 = stack_3f;
                        stack_3c = local_40;
                        stack_3b = stack_3f;
                    } else {
                        unimplemented!()
                    }

                    var_8 = u64::from_le_bytes([
                        stack_39, stack_3a, stack_3b, stack_3c, stack_39, stack_3a, stack_3b,
                        stack_3c,
                    ]);

                    next_dst.copy_from(&var_8 as *const u64 as *const u8, 8);
                    next_dst = next_dst.byte_add(8);
                    lit_len = (cur_dst as isize + (7 - next_dst as isize)) >> 3;

                    if cur_dst < next_dst {
                        unimplemented!()
                    }

                    if lit_len != 0 {
                        while lit_len != 0 {
                            next_dst.copy_from(&var_8 as *const u64 as *const u8, 8);
                            next_dst = next_dst.byte_add(8);

                            lit_len -= 1;
                        }
                    }
                } else {
                    if dst_end.byte_sub(5) < cur_dst {
                        unimplemented!()
                    }

                    lit_len = (dst as isize) - (match_off as isize);

                    if lit_len < match_len {
                        unimplemented!()
                    } else {
                        next_dst.copy_from(
                            dict_end.byte_sub(dst as usize).byte_add(match_off as usize),
                            match_len as usize,
                        );
                    }
                }
            }
        }

        unimplemented!()
    }
}

#[test]
fn test_decompress() {
    let src = &[
        0xFE, 0x44, 0x09, 0x00, 0x00, 0x00, 0x05, 0xDB, 0xAA, 0x0E, 0x00, 0xA9, 0x07, 0x00, 0x00,
        0x50, 0xD7, 0xD8, 0x52, 0x53, 0x2F, 0x09, 0x16, 0x00, 0x00, 0x00, 0x4D, 0x4E, 0x74, 0x45,
        0x6B, 0x49, 0x55, 0x7A, 0x53, 0x77, 0x43, 0x56, 0x6C, 0x39, 0x5A, 0x4F, 0x35, 0x64, 0x71,
        0x41, 0x4E, 0x67, 0x0A, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x63, 0x6B, 0x6D, 0x61, 0x6E,
        0x69, 0x61, 0x05, 0x00, 0x00, 0x00, 0x23, 0x53, 0x52, 0x56, 0x23, 0x01, 0x20, 0x00, 0x20,
        0x04, 0x00, 0x00, 0x00, 0x54, 0x65, 0x73, 0x74, 0x00, 0x00, 0x02, 0x00, 0x13, 0x18, 0x12,
        0x00, 0xF6, 0xAB, 0x05, 0x00, 0x00, 0x00, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x32, 0x30, 0x32, 0x34, 0x2D, 0x30, 0x36, 0x2D, 0x31, 0x34,
        0x5F, 0x32, 0x30, 0x5F, 0x30, 0x30, 0x10, 0x00, 0x00, 0x00, 0x31, 0x2E, 0x31, 0x2E, 0x30,
        0x2B, 0x32, 0x30, 0x32, 0x33, 0x2D, 0x31, 0x30, 0x2D, 0x30, 0x39, 0x17, 0x01, 0x00, 0x00,
        0xEF, 0xBB, 0xBF, 0xC2, 0x92, 0x24, 0x7A, 0x49, 0x6E, 0x20, 0x24, 0x3C, 0x24, 0x74, 0x24,
        0x36, 0x46, 0x39, 0x54, 0x69, 0x6D, 0x65, 0x20, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6B, 0x24,
        0x3E, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x6F, 0x61,
        0x6C, 0x20, 0x69, 0x73, 0x20, 0x74, 0x6F, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x24, 0x3C, 0x24, 0x74, 0x24, 0x36, 0x46, 0x39, 0x62, 0x65, 0x73, 0x74, 0x20, 0x74,
        0x69, 0x6D, 0x65, 0x24, 0x3E, 0x2E, 0x0A, 0x0A, 0x59, 0x6F, 0x75, 0x20, 0x68, 0x61, 0x76,
        0x65, 0x20, 0x61, 0x73, 0x20, 0x6D, 0x61, 0x6E, 0x79, 0x20, 0x74, 0x72, 0x69, 0x65, 0x73,
        0x20, 0x61, 0x73, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x2C, 0x20, 0x61,
        0x6E, 0x64, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x63, 0x61, 0x79, 0x00, 0xC5, 0x72, 0x65, 0x74,
        0x72, 0x79, 0x24, 0x3E, 0x20, 0x77, 0x68, 0x65, 0x6E, 0x2B, 0x00, 0xC1, 0x20, 0x62, 0x79,
        0x20, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x87, 0x00, 0xF1, 0x06, 0x72, 0x65,
        0x73, 0x70, 0x61, 0x77, 0x6E, 0x20, 0x62, 0x75, 0x74, 0x74, 0x6F, 0x6E, 0x2E, 0x0A, 0x0A,
        0x57, 0x68, 0x65, 0x6E, 0x1A, 0x00, 0xB1, 0x74, 0x69, 0x6D, 0x65, 0x20, 0x69, 0x73, 0x20,
        0x75, 0x70, 0x2C, 0x10, 0x00, 0x04, 0x9E, 0x00, 0xB1, 0x77, 0x69, 0x6E, 0x6E, 0x65, 0x72,
        0x24, 0x3E, 0x20, 0x69, 0x73, 0x18, 0x00, 0xB1, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20,
        0x77, 0x69, 0x74, 0x68, 0x10, 0x00, 0x04, 0x28, 0x00, 0x08, 0xC6, 0x00, 0x23, 0x42, 0x00,
        0x1B, 0x01, 0xF3, 0x10, 0x54, 0x59, 0x50, 0x45, 0x3A, 0x20, 0x46, 0x72, 0x65, 0x65, 0x20,
        0x66, 0x6F, 0x72, 0x20, 0x61, 0x6C, 0x6C, 0x0A, 0x4F, 0x42, 0x4A, 0x45, 0x43, 0x54, 0x49,
        0x56, 0x45, 0x3A, 0x20, 0x53, 0x09, 0x01, 0x05, 0x3B, 0x00, 0x23, 0x20, 0x6F, 0x8C, 0x00,
        0x63, 0x72, 0x61, 0x63, 0x6B, 0x2E, 0x03, 0x9E, 0x01, 0xF9, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0xEB, 0x01, 0x82, 0x2F,
        0x54, 0x4D, 0x5F, 0x54, 0x69, 0x6D, 0x65, 0x72, 0x01, 0x77, 0x5F, 0x4F, 0x6E, 0x6C, 0x69,
        0x6E, 0x65, 0xB6, 0x02, 0x62, 0x19, 0x19, 0x00, 0x00, 0x00, 0x0D, 0x33, 0x00, 0xFD, 0x01,
        0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x33, 0x2E, 0x22, 0x00, 0x00, 0xEE,
        0x01, 0x18, 0x00, 0x6E, 0x34, 0x2E, 0x22, 0x00, 0x00, 0xE1, 0x18, 0x00, 0x7D, 0x35, 0xCC,
        0x29, 0x00, 0x00, 0x97, 0x02, 0x30, 0x00, 0x6E, 0x36, 0x0C, 0x30, 0x00, 0x00, 0x01, 0x18,
        0x00, 0x6E, 0x37, 0xD0, 0x20, 0x00, 0x00, 0x53, 0x18, 0x00, 0x6E, 0x38, 0x44, 0x2F, 0x00,
        0x00, 0x96, 0x18, 0x00, 0x6D, 0x39, 0x70, 0x30, 0x00, 0x00, 0x60, 0x18, 0x00, 0x8C, 0x31,
        0x30, 0x12, 0x2F, 0x00, 0x00, 0x57, 0x03, 0x78, 0x00, 0x7D, 0x31, 0x31, 0x1E, 0x14, 0x00,
        0x00, 0xB8, 0xA8, 0x00, 0x7E, 0x31, 0x32, 0xD4, 0x30, 0x00, 0x00, 0xDD, 0x18, 0x00, 0x6E,
        0x33, 0xBC, 0x34, 0x00, 0x00, 0xD4, 0x60, 0x00, 0x6E, 0x34, 0xC8, 0x32, 0x00, 0x00, 0x4F,
        0x18, 0x00, 0x6E, 0x35, 0xB6, 0x35, 0x00, 0x00, 0x73, 0x18, 0x00, 0x6E, 0x36, 0x74, 0x40,
        0x00, 0x00, 0x61, 0x18, 0x00, 0x6E, 0x37, 0x38, 0x4A, 0x00, 0x00, 0x76, 0x18, 0x00, 0x6E,
        0x38, 0x68, 0x42, 0x00, 0x00, 0x78, 0x18, 0x00, 0x6D, 0x39, 0xFC, 0x53, 0x00, 0x00, 0xAB,
        0x18, 0x00, 0x7D, 0x32, 0x30, 0x30, 0x75, 0x00, 0x00, 0x4D, 0xF0, 0x00, 0x7E, 0x32, 0x31,
        0x50, 0x46, 0x00, 0x00, 0x23, 0x30, 0x00, 0x3F, 0x32, 0x20, 0x4E, 0x18, 0x00, 0x02, 0x3F,
        0x33, 0x90, 0x65, 0x18, 0x00, 0x02, 0x3F, 0x34, 0x08, 0x52, 0x18, 0x00, 0x02, 0x6D, 0x35,
        0x40, 0x9C, 0x00, 0x00, 0x37, 0x78, 0x00, 0x7D, 0x30, 0x31, 0x40, 0x1F, 0x00, 0x00, 0xDB,
        0x50, 0x01, 0x81, 0x30, 0x32, 0x84, 0x1C, 0x00, 0x00, 0xDC, 0x01, 0x8F, 0x02, 0xF0, 0xFF,
        0xFF, 0xFF, 0x02, 0x03, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x01, 0x1B, 0x00, 0x00,
        0x00, 0x6C, 0x4E, 0x50, 0x38, 0x4F, 0x30, 0x73, 0x71, 0x61, 0x74, 0x69, 0x48, 0x71, 0x65,
        0x63, 0x55, 0x58, 0x72, 0x68, 0x48, 0x36, 0x35, 0x72, 0x70, 0x51, 0x38, 0x61, 0x1B, 0x00,
        0x00, 0x00, 0x67, 0x61, 0x33, 0x7A, 0x54, 0x4B, 0x76, 0x53, 0x6F, 0x37, 0x79, 0x4A, 0x63,
        0x61, 0x36, 0x30, 0x52, 0x79, 0x5F, 0x5A, 0x30, 0x30, 0x33, 0x4C, 0x30, 0x33, 0x31, 0x1B,
        0x00, 0x00, 0x00, 0x78, 0x53, 0x4F, 0x41, 0x33, 0x46, 0x73, 0x38, 0x6B, 0x33, 0x62, 0x47,
        0x4E, 0x48, 0x46, 0x51, 0x68, 0x77, 0x73, 0x6B, 0x79, 0x41, 0x6A, 0x4E, 0x33, 0x4E, 0x68,
        0x1B, 0x00, 0x00, 0x00, 0x4C, 0x63, 0x42, 0x61, 0x34, 0x4F, 0x5A, 0x4C, 0x65, 0x45, 0x6C,
        0x6E, 0x4A, 0x6B, 0x73, 0x67, 0x62, 0x42, 0x45, 0x70, 0x51, 0x67, 0x67, 0x69, 0x74, 0x73,
        0x68, 0x1B, 0x00, 0x00, 0x00, 0x76, 0x54, 0x71, 0x55, 0x70, 0x45, 0x31, 0x69, 0x69, 0x58,
        0x75, 0x70, 0x4E, 0x41, 0x42, 0x70, 0x35, 0x4D, 0x66, 0x78, 0x30, 0x59, 0x4F, 0x66, 0x33,
        0x33, 0x6A, 0x1B, 0x00, 0x00, 0x00, 0x4F, 0x65, 0x4A, 0x43, 0x57, 0x38, 0x73, 0x48, 0x45,
        0x4E, 0x49, 0x63, 0x59, 0x73, 0x63, 0x4B, 0x38, 0x6F, 0x35, 0x7A, 0x56, 0x48, 0x41, 0x78,
        0x41, 0x44, 0x64, 0x1B, 0x00, 0x00, 0x00, 0x75, 0x73, 0x34, 0x67, 0x61, 0x43, 0x44, 0x51,
        0x53, 0x78, 0x6D, 0x6A, 0x56, 0x4D, 0x74, 0x70, 0x35, 0x6E, 0x59, 0x66, 0x52, 0x65, 0x65,
        0x7A, 0x54, 0x71, 0x68, 0x1B, 0x00, 0x00, 0x00, 0x44, 0x79, 0x4E, 0x42, 0x78, 0x68, 0x51,
        0x36, 0x30, 0x30, 0x36, 0x39, 0x39, 0x31, 0x46, 0x77, 0x76, 0x56, 0x4F, 0x61, 0x42, 0x58,
        0x39, 0x47, 0x63, 0x76, 0x31, 0x1A, 0x00, 0x00, 0x00, 0x50, 0x68, 0x4A, 0x47, 0x76, 0x47,
        0x6A, 0x6B, 0x43, 0x61, 0x77, 0x32, 0x39, 0x39, 0x72, 0x42, 0x68, 0x56, 0x73, 0x45, 0x68,
        0x4E, 0x4A, 0x4B, 0x58, 0x31, 0x1B, 0x00, 0x00, 0x00, 0x41, 0x4A, 0x46, 0x4A, 0x64, 0x36,
        0x79, 0x41, 0x42, 0x75, 0x53, 0x4D, 0x66, 0x67, 0x4A, 0x47, 0x63, 0x38, 0x55, 0x70, 0x57,
        0x52, 0x77, 0x55, 0x56, 0x61, 0x30, 0x1B, 0x00, 0x00, 0x00, 0x4E, 0x77, 0x38, 0x42, 0x5A,
        0x38, 0x43, 0x74, 0x5A, 0x5A, 0x63, 0x46, 0x4F, 0x35, 0x34, 0x37, 0x57, 0x6E, 0x71, 0x64,
        0x50, 0x7A, 0x70, 0x38, 0x79, 0x64, 0x69, 0x1B, 0x00, 0x00, 0x00, 0x65, 0x4F, 0x41, 0x31,
        0x58, 0x5F, 0x78, 0x6E, 0x76, 0x4B, 0x62, 0x64, 0x44, 0x53, 0x75, 0x79, 0x79, 0x6D, 0x77,
        0x65, 0x4F, 0x5A, 0x7A, 0x53, 0x72, 0x51, 0x33, 0x1A, 0x00, 0x00, 0x00, 0x30, 0x68, 0x49,
        0x32, 0x50, 0x33, 0x79, 0x38, 0x73, 0x45, 0x4E, 0x67, 0x49, 0x6B, 0x72, 0x75, 0x49, 0x5F,
        0x58, 0x37, 0x73, 0x33, 0x65, 0x66, 0x45, 0x53, 0x1B, 0x00, 0x00, 0x00, 0x52, 0x6C, 0x5A,
        0x32, 0x48, 0x56, 0x68, 0x41, 0x77, 0x4E, 0x35, 0x6E, 0x44, 0x37, 0x49, 0x31, 0x6C, 0x4C,
        0x63, 0x69, 0x4B, 0x68, 0x50, 0x73, 0x62, 0x62, 0x37, 0x1B, 0x00, 0x00, 0x00, 0x45, 0x6E,
        0x4D, 0x6E, 0x42, 0x67, 0x33, 0x44, 0x34, 0x55, 0x76, 0x62, 0x35, 0x62, 0x7A, 0x38, 0x56,
        0x4C, 0x6F, 0x64, 0x37, 0x33, 0x7A, 0x36, 0x6E, 0x34, 0x37, 0x1B, 0x00, 0x00, 0x00, 0x54,
        0x56, 0x55, 0x46, 0x39, 0x31, 0x59, 0x6C, 0x6E, 0x4C, 0x37, 0x38, 0x42, 0x46, 0x4A, 0x77,
        0x47, 0x35, 0x41, 0x44, 0x6B, 0x4E, 0x6C, 0x79, 0x6D, 0x71, 0x65, 0x1B, 0x00, 0x00, 0x00,
        0x53, 0x73, 0x43, 0x64, 0x4C, 0x36, 0x6E, 0x47, 0x43, 0x5F, 0x5F, 0x6E, 0x38, 0x55, 0x72,
        0x59, 0x6E, 0x73, 0x58, 0x38, 0x78, 0x61, 0x71, 0x6E, 0x6A, 0x43, 0x68, 0x1B, 0x00, 0x00,
        0x00, 0x59, 0x61, 0x6B, 0x7A, 0x38, 0x78, 0x44, 0x6C, 0x56, 0x57, 0x44, 0x66, 0x56, 0x43,
        0x66, 0x58, 0x78, 0x57, 0x32, 0x5F, 0x70, 0x61, 0x43, 0x61, 0x48, 0x69, 0x6C, 0x1B, 0x00,
        0x00, 0x00, 0x66, 0x31, 0x74, 0x6C, 0x4F, 0x7A, 0x58, 0x76, 0x64, 0x45, 0x4C, 0x56, 0x68,
        0x77, 0x72, 0x68, 0x50, 0x70, 0x6F, 0x4A, 0x44, 0x73, 0x67, 0x39, 0x78, 0x73, 0x38, 0x1B,
        0x00, 0x00, 0x00, 0x4F, 0x48, 0x52, 0x78, 0x4A, 0x43, 0x45, 0x5F, 0x63, 0x4B, 0x78, 0x45,
        0x47, 0x4F, 0x47, 0x6D, 0x68, 0x46, 0x39, 0x7A, 0x36, 0x48, 0x66, 0x30, 0x59, 0x5A, 0x62,
        0x1B, 0x00, 0x00, 0x00, 0x71, 0x51, 0x45, 0x67, 0x4E, 0x4B, 0x78, 0x44, 0x68, 0x58, 0x74,
        0x54, 0x73, 0x78, 0x57, 0x59, 0x52, 0x57, 0x30, 0x56, 0x34, 0x70, 0x76, 0x70, 0x45, 0x52,
        0x37, 0x1B, 0x00, 0x00, 0x00, 0x31, 0x72, 0x77, 0x41, 0x6B, 0x4C, 0x72, 0x62, 0x71, 0x68,
        0x4E, 0x34, 0x37, 0x7A, 0x43, 0x73, 0x56, 0x76, 0x4A, 0x4A, 0x46, 0x4A, 0x69, 0x6D, 0x6C,
        0x63, 0x66, 0x1B, 0x00, 0x00, 0x00, 0x54, 0x6B, 0x79, 0x4B, 0x73, 0x4F, 0x45, 0x47, 0x37,
        0x67, 0x48, 0x71, 0x56, 0x71, 0x6A, 0x6A, 0x63, 0x33, 0x41, 0x31, 0x51, 0x6A, 0x35, 0x72,
        0x50, 0x67, 0x69, 0x1B, 0x00, 0x00, 0x00, 0x6F, 0x6C, 0x73, 0x4B, 0x6E, 0x71, 0x5F, 0x71,
        0x41, 0x67, 0x68, 0x63, 0x56, 0x41, 0x6E, 0x45, 0x6B, 0x6F, 0x65, 0x55, 0x6E, 0x56, 0x48,
        0x46, 0x5A, 0x65, 0x69, 0x1B, 0x00, 0x00, 0x00, 0x62, 0x74, 0x6D, 0x62, 0x4A, 0x57, 0x41,
        0x44, 0x51, 0x4F, 0x53, 0x32, 0x30, 0x67, 0x69, 0x6E, 0x50, 0x39, 0x44, 0x4A, 0x30, 0x69,
        0x38, 0x73, 0x68, 0x33, 0x66,
    ];

    let dst = &mut [0; 1974];

    let dict = &[
        0x47, 0x42, 0x58, 0x06, 0x00, 0x42, 0x55, 0x55, 0x52, 0x00, 0x50, 0x00, 0x09, 0x00, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x47, 0x42, 0x58, 0x06, 0x00, 0x42,
        0x55, 0x43, 0x52, 0x00, 0xD0, 0x10, 0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72,
        0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x22, 0x31, 0x2E, 0x30, 0x22, 0x20, 0x65, 0x6E, 0x63, 0x6F,
        0x64, 0x69, 0x6E, 0x67, 0x3D, 0x22, 0x75, 0x74, 0x66, 0x2D, 0x38, 0x22, 0x20, 0x3F, 0x3E,
        0x0A, 0x3C, 0x6D, 0x61, 0x6E, 0x69, 0x61, 0x6C, 0x69, 0x6E, 0x6B, 0x20, 0x76, 0x65, 0x72,
        0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x22, 0x22, 0x66, 0x69, 0x6C, 0x65, 0x3A, 0x2F, 0x2F, 0x4D,
        0x65, 0x64, 0x69, 0x61, 0x2F, 0x49, 0x6D, 0x61, 0x67, 0x65, 0x73, 0x2F, 0x22, 0x66, 0x69,
        0x6C, 0x65, 0x3A, 0x2F, 0x2F, 0x4D, 0x65, 0x64, 0x69, 0x61, 0x2F, 0x4D, 0x61, 0x6E, 0x69,
        0x61, 0x6C, 0x69, 0x6E, 0x6B, 0x73, 0x2F, 0x43, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x3C, 0x66,
        0x72, 0x61, 0x6D, 0x65, 0x20, 0x69, 0x64, 0x3D, 0x22, 0x3C, 0x6C, 0x61, 0x62, 0x65, 0x6C,
        0x20, 0x69, 0x64, 0x3D, 0x22, 0x3C, 0x71, 0x75, 0x61, 0x64, 0x20, 0x69, 0x64, 0x3D, 0x22,
        0x3C, 0x2F, 0x66, 0x72, 0x61, 0x6D, 0x65, 0x3E, 0x20, 0x2F, 0x3E, 0x0D, 0x0A, 0x23, 0x52,
        0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x20, 0x23,
        0x49, 0x6E, 0x63, 0x6C, 0x75, 0x64, 0x65, 0x20, 0x22, 0x4C, 0x69, 0x62, 0x73, 0x2F, 0x4E,
        0x61, 0x64, 0x65, 0x6F, 0x2F, 0x2E, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x2E, 0x74, 0x78,
        0x74, 0x22, 0x23, 0x43, 0x6F, 0x6E, 0x73, 0x74, 0x20, 0x43, 0x5F, 0x09, 0x64, 0x65, 0x63,
        0x6C, 0x61, 0x72, 0x65, 0x20, 0x54, 0x65, 0x78, 0x74, 0x20, 0x79, 0x69, 0x65, 0x6C, 0x64,
        0x3B, 0x66, 0x6F, 0x72, 0x65, 0x61, 0x63, 0x68, 0x28, 0x63, 0x6F, 0x6E, 0x74, 0x69, 0x6E,
        0x75, 0x65, 0x3B, 0x6D, 0x61, 0x69, 0x6E, 0x28, 0x29, 0x42, 0x6F, 0x6F, 0x6C, 0x65, 0x61,
        0x6E, 0x49, 0x6E, 0x74, 0x65, 0x67, 0x65, 0x72, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x28,
        0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x3B, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x3F, 0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    ];

    let dst_len = decompress(src, dst, dict).unwrap();

    let expected_dst = &[
        0x09, 0x00, 0x00, 0x00, 0x05, 0xDB, 0xAA, 0x0E, 0x00, 0xA9, 0x07, 0x00, 0x00, 0x50, 0xD7,
        0xD8, 0x52, 0x53, 0x2F, 0x09, 0x16, 0x00, 0x00, 0x00, 0x4D, 0x4E, 0x74, 0x45, 0x6B, 0x49,
        0x55, 0x7A, 0x53, 0x77, 0x43, 0x56, 0x6C, 0x39, 0x5A, 0x4F, 0x35, 0x64, 0x71, 0x41, 0x4E,
        0x67, 0x0A, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x63, 0x6B, 0x6D, 0x61, 0x6E, 0x69, 0x61,
        0x05, 0x00, 0x00, 0x00, 0x23, 0x53, 0x52, 0x56, 0x23, 0x01, 0x20, 0x00, 0x20, 0x04, 0x00,
        0x00, 0x00, 0x54, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x32, 0x30, 0x32, 0x34, 0x2D, 0x30, 0x36, 0x2D, 0x31,
        0x34, 0x5F, 0x32, 0x30, 0x5F, 0x30, 0x30, 0x10, 0x00, 0x00, 0x00, 0x31, 0x2E, 0x31, 0x2E,
        0x30, 0x2B, 0x32, 0x30, 0x32, 0x33, 0x2D, 0x31, 0x30, 0x2D, 0x30, 0x39, 0x17, 0x01, 0x00,
        0x00, 0xEF, 0xBB, 0xBF, 0xC2, 0x92, 0x24, 0x7A, 0x49, 0x6E, 0x20, 0x24, 0x3C, 0x24, 0x74,
        0x24, 0x36, 0x46, 0x39, 0x54, 0x69, 0x6D, 0x65, 0x20, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6B,
        0x24, 0x3E, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x6F,
        0x61, 0x6C, 0x20, 0x69, 0x73, 0x20, 0x74, 0x6F, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x68,
        0x65, 0x20, 0x24, 0x3C, 0x24, 0x74, 0x24, 0x36, 0x46, 0x39, 0x62, 0x65, 0x73, 0x74, 0x20,
        0x74, 0x69, 0x6D, 0x65, 0x24, 0x3E, 0x2E, 0x0A, 0x0A, 0x59, 0x6F, 0x75, 0x20, 0x68, 0x61,
        0x76, 0x65, 0x20, 0x61, 0x73, 0x20, 0x6D, 0x61, 0x6E, 0x79, 0x20, 0x74, 0x72, 0x69, 0x65,
        0x73, 0x20, 0x61, 0x73, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x2C, 0x20,
        0x61, 0x6E, 0x64, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x63, 0x61, 0x6E, 0x20, 0x24, 0x3C, 0x24,
        0x74, 0x24, 0x36, 0x46, 0x39, 0x72, 0x65, 0x74, 0x72, 0x79, 0x24, 0x3E, 0x20, 0x77, 0x68,
        0x65, 0x6E, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x62, 0x79, 0x20,
        0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65,
        0x73, 0x70, 0x61, 0x77, 0x6E, 0x20, 0x62, 0x75, 0x74, 0x74, 0x6F, 0x6E, 0x2E, 0x0A, 0x0A,
        0x57, 0x68, 0x65, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20, 0x69,
        0x73, 0x20, 0x75, 0x70, 0x2C, 0x20, 0x74, 0x68, 0x65, 0x20, 0x24, 0x3C, 0x24, 0x74, 0x24,
        0x36, 0x46, 0x39, 0x77, 0x69, 0x6E, 0x6E, 0x65, 0x72, 0x24, 0x3E, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x77, 0x69, 0x74, 0x68,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x24, 0x3C, 0x24, 0x74, 0x24, 0x36, 0x46, 0x39, 0x62, 0x65,
        0x73, 0x74, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x24, 0x3E, 0x2E, 0x42, 0x00, 0x00, 0x00, 0xEF,
        0xBB, 0xBF, 0xC2, 0x92, 0x54, 0x59, 0x50, 0x45, 0x3A, 0x20, 0x46, 0x72, 0x65, 0x65, 0x20,
        0x66, 0x6F, 0x72, 0x20, 0x61, 0x6C, 0x6C, 0x0A, 0x4F, 0x42, 0x4A, 0x45, 0x43, 0x54, 0x49,
        0x56, 0x45, 0x3A, 0x20, 0x53, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x65, 0x73,
        0x74, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
        0x72, 0x61, 0x63, 0x6B, 0x2E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x63, 0x6B, 0x6D, 0x61, 0x6E, 0x69, 0x61, 0x2F, 0x54, 0x4D, 0x5F,
        0x54, 0x69, 0x6D, 0x65, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6B, 0x5F, 0x4F, 0x6E, 0x6C, 0x69,
        0x6E, 0x65, 0x2E, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x2E, 0x74, 0x78, 0x74, 0x19, 0x19,
        0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x2D, 0x20, 0x30, 0x33, 0x2E, 0x22, 0x00, 0x00, 0xEE, 0x01, 0x00, 0x0D, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x34, 0x2E,
        0x22, 0x00, 0x00, 0xE1, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x35, 0xCC, 0x29, 0x00, 0x00, 0x97, 0x02, 0x00,
        0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20,
        0x30, 0x36, 0x0C, 0x30, 0x00, 0x00, 0x01, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72,
        0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x37, 0xD0, 0x20, 0x00, 0x00,
        0x53, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x2D, 0x20, 0x30, 0x38, 0x44, 0x2F, 0x00, 0x00, 0x96, 0x02, 0x00, 0x0D, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x39, 0x70,
        0x30, 0x00, 0x00, 0x60, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x30, 0x12, 0x2F, 0x00, 0x00, 0x57, 0x03, 0x00,
        0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20,
        0x31, 0x31, 0x1E, 0x14, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72,
        0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x32, 0xD4, 0x30, 0x00, 0x00,
        0xDD, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x2D, 0x20, 0x31, 0x33, 0xBC, 0x34, 0x00, 0x00, 0xD4, 0x02, 0x00, 0x0D, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x34, 0xC8,
        0x32, 0x00, 0x00, 0x4F, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x35, 0xB6, 0x35, 0x00, 0x00, 0x73, 0x02, 0x00,
        0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20,
        0x31, 0x36, 0x74, 0x40, 0x00, 0x00, 0x61, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72,
        0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x37, 0x38, 0x4A, 0x00, 0x00,
        0x76, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x2D, 0x20, 0x31, 0x38, 0x68, 0x42, 0x00, 0x00, 0x78, 0x02, 0x00, 0x0D, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x31, 0x39, 0xFC,
        0x53, 0x00, 0x00, 0xAB, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x32, 0x30, 0x30, 0x75, 0x00, 0x00, 0x4D, 0x03, 0x00,
        0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20,
        0x32, 0x31, 0x50, 0x46, 0x00, 0x00, 0x23, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72,
        0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x32, 0x32, 0x20, 0x4E, 0x00, 0x00,
        0x23, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x2D, 0x20, 0x32, 0x33, 0x90, 0x65, 0x00, 0x00, 0x23, 0x02, 0x00, 0x0D, 0x00, 0x00,
        0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x32, 0x34, 0x08,
        0x52, 0x00, 0x00, 0x23, 0x02, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E,
        0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x32, 0x35, 0x40, 0x9C, 0x00, 0x00, 0x37, 0x03, 0x00,
        0x0D, 0x00, 0x00, 0x00, 0x54, 0x72, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20,
        0x30, 0x31, 0x40, 0x1F, 0x00, 0x00, 0xDB, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x54, 0x72,
        0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x2D, 0x20, 0x30, 0x32, 0x84, 0x1C, 0x00, 0x00,
        0xDC, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00,
        0x01, 0x1B, 0x00, 0x00, 0x00, 0x6C, 0x4E, 0x50, 0x38, 0x4F, 0x30, 0x73, 0x71, 0x61, 0x74,
        0x69, 0x48, 0x71, 0x65, 0x63, 0x55, 0x58, 0x72, 0x68, 0x48, 0x36, 0x35, 0x72, 0x70, 0x51,
        0x38, 0x61, 0x1B, 0x00, 0x00, 0x00, 0x67, 0x61, 0x33, 0x7A, 0x54, 0x4B, 0x76, 0x53, 0x6F,
        0x37, 0x79, 0x4A, 0x63, 0x61, 0x36, 0x30, 0x52, 0x79, 0x5F, 0x5A, 0x30, 0x30, 0x33, 0x4C,
        0x30, 0x33, 0x31, 0x1B, 0x00, 0x00, 0x00, 0x78, 0x53, 0x4F, 0x41, 0x33, 0x46, 0x73, 0x38,
        0x6B, 0x33, 0x62, 0x47, 0x4E, 0x48, 0x46, 0x51, 0x68, 0x77, 0x73, 0x6B, 0x79, 0x41, 0x6A,
        0x4E, 0x33, 0x4E, 0x68, 0x1B, 0x00, 0x00, 0x00, 0x4C, 0x63, 0x42, 0x61, 0x34, 0x4F, 0x5A,
        0x4C, 0x65, 0x45, 0x6C, 0x6E, 0x4A, 0x6B, 0x73, 0x67, 0x62, 0x42, 0x45, 0x70, 0x51, 0x67,
        0x67, 0x69, 0x74, 0x73, 0x68, 0x1B, 0x00, 0x00, 0x00, 0x76, 0x54, 0x71, 0x55, 0x70, 0x45,
        0x31, 0x69, 0x69, 0x58, 0x75, 0x70, 0x4E, 0x41, 0x42, 0x70, 0x35, 0x4D, 0x66, 0x78, 0x30,
        0x59, 0x4F, 0x66, 0x33, 0x33, 0x6A, 0x1B, 0x00, 0x00, 0x00, 0x4F, 0x65, 0x4A, 0x43, 0x57,
        0x38, 0x73, 0x48, 0x45, 0x4E, 0x49, 0x63, 0x59, 0x73, 0x63, 0x4B, 0x38, 0x6F, 0x35, 0x7A,
        0x56, 0x48, 0x41, 0x78, 0x41, 0x44, 0x64, 0x1B, 0x00, 0x00, 0x00, 0x75, 0x73, 0x34, 0x67,
        0x61, 0x43, 0x44, 0x51, 0x53, 0x78, 0x6D, 0x6A, 0x56, 0x4D, 0x74, 0x70, 0x35, 0x6E, 0x59,
        0x66, 0x52, 0x65, 0x65, 0x7A, 0x54, 0x71, 0x68, 0x1B, 0x00, 0x00, 0x00, 0x44, 0x79, 0x4E,
        0x42, 0x78, 0x68, 0x51, 0x36, 0x30, 0x30, 0x36, 0x39, 0x39, 0x31, 0x46, 0x77, 0x76, 0x56,
        0x4F, 0x61, 0x42, 0x58, 0x39, 0x47, 0x63, 0x76, 0x31, 0x1A, 0x00, 0x00, 0x00, 0x50, 0x68,
        0x4A, 0x47, 0x76, 0x47, 0x6A, 0x6B, 0x43, 0x61, 0x77, 0x32, 0x39, 0x39, 0x72, 0x42, 0x68,
        0x56, 0x73, 0x45, 0x68, 0x4E, 0x4A, 0x4B, 0x58, 0x31, 0x1B, 0x00, 0x00, 0x00, 0x41, 0x4A,
        0x46, 0x4A, 0x64, 0x36, 0x79, 0x41, 0x42, 0x75, 0x53, 0x4D, 0x66, 0x67, 0x4A, 0x47, 0x63,
        0x38, 0x55, 0x70, 0x57, 0x52, 0x77, 0x55, 0x56, 0x61, 0x30, 0x1B, 0x00, 0x00, 0x00, 0x4E,
        0x77, 0x38, 0x42, 0x5A, 0x38, 0x43, 0x74, 0x5A, 0x5A, 0x63, 0x46, 0x4F, 0x35, 0x34, 0x37,
        0x57, 0x6E, 0x71, 0x64, 0x50, 0x7A, 0x70, 0x38, 0x79, 0x64, 0x69, 0x1B, 0x00, 0x00, 0x00,
        0x65, 0x4F, 0x41, 0x31, 0x58, 0x5F, 0x78, 0x6E, 0x76, 0x4B, 0x62, 0x64, 0x44, 0x53, 0x75,
        0x79, 0x79, 0x6D, 0x77, 0x65, 0x4F, 0x5A, 0x7A, 0x53, 0x72, 0x51, 0x33, 0x1A, 0x00, 0x00,
        0x00, 0x30, 0x68, 0x49, 0x32, 0x50, 0x33, 0x79, 0x38, 0x73, 0x45, 0x4E, 0x67, 0x49, 0x6B,
        0x72, 0x75, 0x49, 0x5F, 0x58, 0x37, 0x73, 0x33, 0x65, 0x66, 0x45, 0x53, 0x1B, 0x00, 0x00,
        0x00, 0x52, 0x6C, 0x5A, 0x32, 0x48, 0x56, 0x68, 0x41, 0x77, 0x4E, 0x35, 0x6E, 0x44, 0x37,
        0x49, 0x31, 0x6C, 0x4C, 0x63, 0x69, 0x4B, 0x68, 0x50, 0x73, 0x62, 0x62, 0x37, 0x1B, 0x00,
        0x00, 0x00, 0x45, 0x6E, 0x4D, 0x6E, 0x42, 0x67, 0x33, 0x44, 0x34, 0x55, 0x76, 0x62, 0x35,
        0x62, 0x7A, 0x38, 0x56, 0x4C, 0x6F, 0x64, 0x37, 0x33, 0x7A, 0x36, 0x6E, 0x34, 0x37, 0x1B,
        0x00, 0x00, 0x00, 0x54, 0x56, 0x55, 0x46, 0x39, 0x31, 0x59, 0x6C, 0x6E, 0x4C, 0x37, 0x38,
        0x42, 0x46, 0x4A, 0x77, 0x47, 0x35, 0x41, 0x44, 0x6B, 0x4E, 0x6C, 0x79, 0x6D, 0x71, 0x65,
        0x1B, 0x00, 0x00, 0x00, 0x53, 0x73, 0x43, 0x64, 0x4C, 0x36, 0x6E, 0x47, 0x43, 0x5F, 0x5F,
        0x6E, 0x38, 0x55, 0x72, 0x59, 0x6E, 0x73, 0x58, 0x38, 0x78, 0x61, 0x71, 0x6E, 0x6A, 0x43,
        0x68, 0x1B, 0x00, 0x00, 0x00, 0x59, 0x61, 0x6B, 0x7A, 0x38, 0x78, 0x44, 0x6C, 0x56, 0x57,
        0x44, 0x66, 0x56, 0x43, 0x66, 0x58, 0x78, 0x57, 0x32, 0x5F, 0x70, 0x61, 0x43, 0x61, 0x48,
        0x69, 0x6C, 0x1B, 0x00, 0x00, 0x00, 0x66, 0x31, 0x74, 0x6C, 0x4F, 0x7A, 0x58, 0x76, 0x64,
        0x45, 0x4C, 0x56, 0x68, 0x77, 0x72, 0x68, 0x50, 0x70, 0x6F, 0x4A, 0x44, 0x73, 0x67, 0x39,
        0x78, 0x73, 0x38, 0x1B, 0x00, 0x00, 0x00, 0x4F, 0x48, 0x52, 0x78, 0x4A, 0x43, 0x45, 0x5F,
        0x63, 0x4B, 0x78, 0x45, 0x47, 0x4F, 0x47, 0x6D, 0x68, 0x46, 0x39, 0x7A, 0x36, 0x48, 0x66,
        0x30, 0x59, 0x5A, 0x62, 0x1B, 0x00, 0x00, 0x00, 0x71, 0x51, 0x45, 0x67, 0x4E, 0x4B, 0x78,
        0x44, 0x68, 0x58, 0x74, 0x54, 0x73, 0x78, 0x57, 0x59, 0x52, 0x57, 0x30, 0x56, 0x34, 0x70,
        0x76, 0x70, 0x45, 0x52, 0x37, 0x1B, 0x00, 0x00, 0x00, 0x31, 0x72, 0x77, 0x41, 0x6B, 0x4C,
        0x72, 0x62, 0x71, 0x68, 0x4E, 0x34, 0x37, 0x7A, 0x43, 0x73, 0x56, 0x76, 0x4A, 0x4A, 0x46,
        0x4A, 0x69, 0x6D, 0x6C, 0x63, 0x66, 0x1B, 0x00, 0x00, 0x00, 0x54, 0x6B, 0x79, 0x4B, 0x73,
        0x4F, 0x45, 0x47, 0x37, 0x67, 0x48, 0x71, 0x56, 0x71, 0x6A, 0x6A, 0x63, 0x33, 0x41, 0x31,
        0x51, 0x6A, 0x35, 0x72, 0x50, 0x67, 0x69, 0x1B, 0x00, 0x00, 0x00, 0x6F, 0x6C, 0x73, 0x4B,
        0x6E, 0x71, 0x5F, 0x71, 0x41, 0x67, 0x68, 0x63, 0x56, 0x41, 0x6E, 0x45, 0x6B, 0x6F, 0x65,
        0x55, 0x6E, 0x56, 0x48, 0x46, 0x5A, 0x65, 0x69, 0x1B, 0x00, 0x00, 0x00, 0x62, 0x74, 0x6D,
        0x62, 0x4A, 0x57, 0x41, 0x44, 0x51, 0x4F, 0x53, 0x32, 0x30, 0x67, 0x69, 0x6E, 0x50, 0x39,
        0x44, 0x4A, 0x30, 0x69, 0x38, 0x73, 0x68, 0x33, 0x66,
    ];

    assert_eq!(dst_len, expected_dst.len());
    assert_eq!(dst, expected_dst);
}
