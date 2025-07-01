import math

def text_to_block(text, block_size=256, text_char_blank=True, valid_chars=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'):
    blocks = []
    valid_chars_length = len(valid_chars) + 1*bool(text_char_blank)
    valid_chars_dict = {char: idx+1*bool(text_char_blank) for idx, char in enumerate(valid_chars)}
    texts_per_block = math.floor(block_size * math.log(2, valid_chars_length ) + 1e-15)
    multiply_base = [1]  # valid_chars_length^0
    for i in range(1, texts_per_block):
        multiply_base.append(multiply_base[-1] * valid_chars_length)
    invalid_chars = set(text) - valid_chars_dict.keys()
    if invalid_chars:
        raise ValueError(f"Invalid characters: {invalid_chars}")
    for i in range(0, len(text), texts_per_block):
        text_in_block = text[i:i + texts_per_block]
        block_bit = 0
        block_bit = sum(
            valid_chars_dict[char] * multiply_base[char_idx]
            for char_idx, char in enumerate(text_in_block[::-1])
        )
        blocks.append(block_bit)
    return blocks

def block_to_text(blocks, block_size=256, text_char_blank=True, valid_chars=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'):
    valid_chars_length = len(valid_chars) + 1*bool(text_char_blank)
    log_factor = math.log(2, valid_chars_length)
    texts_per_block = math.floor(block_size * log_factor + 1e-15)
    multiply_base = [1]  # valid_chars_length^0
    for i in range(1, texts_per_block):
        multiply_base.append(multiply_base[-1] * valid_chars_length)
    multiply_base.reverse()
    valid_chars_index = [None]*bool(text_char_blank) + list(valid_chars)
    text = []
    for block in blocks:
        remaining = block
        block_text = []
        for base in multiply_base:
            if remaining == 0: break  # 提前终止，减少不必要的迭代
            char_idx = remaining // base
            remaining %= base  # 更新余数
            ok=0
            while ok<=0 and ok>=-5:
                try:
                    if char_idx != 0 or not text_char_blank:  block_text.append(valid_chars_index[char_idx])
                    ok=1
                except IndexError:
                    ok-=1
                    multiply_base.append(multiply_base[-1] * valid_chars_length)
        if not text_char_blank :
            block_text += [valid_chars_index[0]]*(texts_per_block-len(block_text))
        text.extend(block_text)
    return ''.join(text)

def decimal_to_base(a, base):
    if a == 0: return [0]
    digits = []
    while a > 0:
        digits.append(a % base)
        a //= base
    return digits[::-1]  #[MSB => LSB]
def base_to_decimal(digits, base):
    result = 0
    for digit in digits:
        result = result * base + digit
    return result


def int_list_to_hex_string(int_list, split="-"):
    return split.join(format(num, 'x') for num in int_list)
def hex_string_to_int_list(hex_str, split="-"):
    return list(filter( (lambda x: x is not None) ,
        [int(part, 16) if part else None for part in hex_str.split(split)]))

def hex_to_base(a, bit_base):
    if a == 0: return [0]
    digits = []
    while a > 0:
        digits.append(a % b)
        a //= b
    return digits[::-1]  #[MSB => LSB]
def base_to_hex(digits, base):
    result = 0
    for digit in digits:
        result = result * b + digit
    return result

def linear_shift_forward(plain_text_block_list, key_block_list, sub_block_size=16):
    sub_block_spaces = 1 << sub_block_size  # 2^sub_block_size
    mask = sub_block_spaces - 1
    cipher_text_block_list = []
    for plain_text_block in plain_text_block_list:
        if isinstance(plain_text_block, int): plain_text_block = [plain_text_block]
        plain_text_subblocks = [j for i in plain_text_block
            for j in decimal_to_base(i, sub_block_spaces)]
        m = len(plain_text_subblocks)
        for _ in range(1):
            for index, i in enumerate(key_block_list):
                temp_i_add = i + (i // 3) + (i // 17)
                temp_index = index + 1
                # Precompute factors for all j
                factors = [temp_index * (j + 2) for j in range(m)]
                for j in range(m):
                    # First operation
                    #plain_text_subblocks[j] = (plain_text_subblocks[j] + temp_i_add + factors[j]) & mask
                    # Second operation if j > 0
                    #if j:
                        prev_val = plain_text_subblocks[j - 1] if m-1 else 0
                        add_term = i + factors[j] + prev_val
                        plain_text_subblocks[j] = (plain_text_subblocks[j] + temp_i_add + add_term) & mask
        cipher_text_block_list.append(plain_text_subblocks)
    return cipher_text_block_list

def linear_shift_backward(cipher_text_block_list, key_block_list, sub_block_size=16):
    sub_block_spaces = 1 << sub_block_size  # 2^sub_block_size
    mask = sub_block_spaces - 1
    plain_text_block_list = []
    for cipher_text_block in cipher_text_block_list:
        if isinstance(cipher_text_block, int): cipher_text_block = [cipher_text_block]
        cipher_text_subblocks = [j  for i in cipher_text_block
            for j in decimal_to_base(i, sub_block_spaces)]
        m = len(cipher_text_subblocks)
        for _ in range(1):  # Reverse the two rounds
            for index in reversed(range(len(key_block_list))):  # Reverse key block iteration
                i = key_block_list[index]
                temp_i_add = i + (i // 3) + (i // 17)
                temp_index = index + 1
                # Precompute factors for all j
                factors = [temp_index * (j + 2) for j in range(m)]
                for j in reversed(range(m)):  # Reverse subblock iteration
                    # Reverse second operation if j > 0
                    #if j:
                        prev_val = cipher_text_subblocks[j - 1] if m-1 else 0
                        add_term = i + factors[j] + prev_val
                        cipher_text_subblocks[j] = (cipher_text_subblocks[j] - temp_i_add - add_term) & mask
                    # Reverse first operation
                    #cipher_text_subblocks[j] = (cipher_text_subblocks[j] - temp_i_add - factors[j]) & mask
        plain_text_block_list.append(cipher_text_subblocks)
    return plain_text_block_list

def linear_swap_forward(plain_text_block_list, key_block_list, sub_block_size=16):
    cipher_text_block_list = []
    sub_block_spaces = 2 ** sub_block_size
    for plain_text_block in plain_text_block_list:
        if isinstance(plain_text_block, int): plain_text_block = [plain_text_block]
        plain_text_subblocks = [j for i in plain_text_block
            for j in decimal_to_base(i, sub_block_spaces)]

        subblocklen = len(plain_text_subblocks)
        if subblocklen == 0:
            cipher_text_block_list.append(0)
            continue
        opralen = subblocklen // 10
        key_len = len(key_block_list)
        for index in range(key_len):
            current_key = key_block_list[index]
            max_j = 4 + opralen + subblocklen//2
            for j in range(max_j):
                current_temp = index + j
                mod_temp = current_temp % subblocklen
                factorA = (mod_temp * (mod_temp + opralen)) % subblocklen
                factorB = (current_temp + 1 + current_key) % subblocklen
                if factorA!=0 and factorB != factorA-1:
                    factorB2 = (factorB + plain_text_subblocks[factorA-1]) % subblocklen
                    if factorB2 != factorA-1: factorB = factorB2
                if factorA != factorB:  # 交换元素
                    plain_text_subblocks[factorA], plain_text_subblocks[factorB] = \
                        plain_text_subblocks[factorB], plain_text_subblocks[factorA]

        cipher_text_block_list.append(plain_text_subblocks)

    return cipher_text_block_list

def linear_swap_backward(cipher_text_block_list, key_block_list, sub_block_size=16):
    plain_text_block_list = []
    sub_block_spaces = 2 ** sub_block_size
    for cipher_text_block in cipher_text_block_list:
        if not cipher_text_block: continue
        if isinstance(cipher_text_block, int): cipher_text_block = [cipher_text_block]
        cipher_text_subblocks = [j  for i in cipher_text_block
            for j in decimal_to_base(i, sub_block_spaces)]

        subblocklen = len(cipher_text_subblocks)
        opralen = subblocklen // 10
        key_len = len(key_block_list)
        for index in reversed(range(key_len)):
            current_key = key_block_list[index]
            max_j = 4 + opralen + subblocklen//2
            for j in reversed(range(max_j)):
                current_temp = index + j
                mod_temp = current_temp % subblocklen
                factorA = (mod_temp * (mod_temp + opralen)) % subblocklen
                factorB = (current_temp + 1 + current_key) % subblocklen
                if factorA!=0 and factorB != factorA-1:
                    factorB2 = (factorB + cipher_text_subblocks[factorA-1]) % subblocklen
                    if factorB2 != factorA-1: factorB = factorB2
                if factorA != factorB: # 交换元素
                    cipher_text_subblocks[factorA], cipher_text_subblocks[factorB] = \
                        cipher_text_subblocks[factorB], cipher_text_subblocks[factorA]
        plain_text_block_list.append(cipher_text_subblocks)
    return plain_text_block_list


def build_sbox(key, size=256):
    # 使用密钥驱动的动态S盒生成
    gf_size = size #2**size
    sbox = list(range(gf_size))
    # Fisher-Yates洗牌算法密钥化
    for i in range(gf_size-1, 0, -1):
        key_idx = (key[i % len(key)] + i) % gf_size
        sbox[i], sbox[key_idx] = sbox[key_idx], sbox[i]
    return sbox

def s_box_forward(plain_text_block_list, key_block_list, sub_block_size=8):
    sub_block_spaces = 2 ** sub_block_size  # subblock_size位子块，共2**种可能
    # 使用密钥生成动态S盒
    s_box = build_sbox(key_block_list, size=sub_block_spaces)
    cipher_text_block_list = []
    for plain_text_block in plain_text_block_list:
        # 将明文块分解为sub_block_size位子块列表
        if isinstance(plain_text_block, int): plain_text_block = [plain_text_block]
        plain_text_subblocks = [j for i in plain_text_block
            for j in decimal_to_base(i, sub_block_spaces)]

        # 行移位变换
        # 将subblock分割成4个字节一行的行数
        num_rows = len(plain_text_subblocks) // 4
        for row_idx in range(num_rows):
            start = row_idx * 4
            end = start + 4
            row = plain_text_subblocks[start:end]
            # 对每行应用移位，移位量为row_idx（与AES一致）
            shift = row_idx % 4  # 确保移位量在0-3之间
            shifted_row = row[-shift:] + row[:-shift] if shift != 0 else row
            plain_text_subblocks[start:end] = shifted_row

        cipher_text_subblocks = []
        for subblock in plain_text_subblocks:
            # 使用S盒替换并加1（确保输出在1 ~ subblock_spaces范围内）
            cipher_text_subblocks.append(s_box[subblock])



        # 将加密后的子块组合为密文块（基数为17）
        cipher_text_block_list.append(cipher_text_subblocks)
    return cipher_text_block_list

def s_box_backward(cipher_text_block_list, key_block_list, sub_block_size=8):
    sub_block_spaces = 2 ** sub_block_size
    # 生成相同的动态S盒
    s_box = build_sbox(key_block_list, size=sub_block_spaces)
    # 构建逆S盒
    reverse_s_box = [s_box.index(x) for x in range(len(s_box))]
    plain_text_block_list = []
    for cipher_text_block in cipher_text_block_list:
        # 将密文块分解为基17的子块列表
        if isinstance(cipher_text_block, int): cipher_text_block = [cipher_text_block]
        cipher_text_subblocks = [j  for i in cipher_text_block
            for j in decimal_to_base(i, sub_block_spaces)]

        plain_text_subblocks = []
        for subblock in cipher_text_subblocks:
            # 减1后通过逆S盒恢复原始子块
            plain_text_subblocks.append(reverse_s_box[subblock])

        # 逆行移位变换
        num_rows = len(plain_text_subblocks) // 4
        for row_idx in range(num_rows):
            start = row_idx * 4
            end = start + 4
            row = plain_text_subblocks[start:end]
            shift = row_idx % 4
            original_row = row[shift:] + row[:shift] if shift != 0 else row
            plain_text_subblocks[start:end] = original_row

        # 组合子块为明文块
        plain_text_block_list.append(plain_text_subblocks)
    return plain_text_block_list

def reverse_subblock(block_list):
    return [i[::-1] for i in block_list]

def key_expansion(master_key, rounds=3):
    def diffusion(arr):
        return [(x * 0x15D + (x >> 3)) & 0xFFFF for x in arr]

    expanded_key = master_key.copy()
    xor_shift_factor = min(3, len(expanded_key)-2)
    for _ in range(rounds):
        expanded_key = diffusion(expanded_key)
        if xor_shift_factor>0:
            expanded_key = [expanded_key[(i+xor_shift_factor)%len(expanded_key)]
                ^ expanded_key[i] for i in range(len(expanded_key))]
    return expanded_key


def generate_processes(key_blocks, pool=None):
    if pool is None:
        pool = {0:2, 1:2, 2:2, 3:2, 4:2, 5:2}
    hash_seed = [k * (i+1) for i, k in enumerate(key_blocks)]
    pool_list = [k for k, v in pool.items() for _ in range(v)]
    indexes = build_sbox(hash_seed, len(pool_list))
    return [pool_list[i] for i in indexes]

def encrypt_bitblock(plain_bitblock_list, key_block_list, sub_block_size = 8):
    sub_block_space = 2**sub_block_size
    key0 = key_expansion(key_block_list)
    key1 = linear_shift_forward([50524, 15702, 39651, 6295, 28348, 12071, 35661, 24141,
        668, 55643, 52851, 62390, 27290, 6457, 47093, 44059,
        43598, 34032, 50543, 5357, 14609, 24947, 28090, 1781,
        50795, 30647, 35077, 56306, 37512, 41124, 19279, 43475,
        52403, 730, 43513, 33090, 58988, 20101, 65008, 14513,
        38901, 20626, 62788, 13864, 44670, 12842, 6564, 26644,
        42699, 31359, 31127, 15088, 45717, 57093, 63113, 30010,
        15897, 13744, 405, 50, 1302, 15370, 4377, 8190][:max(256//sub_block_size, 16)],
        key0, sub_block_size*2)
    key1 = [base_to_decimal(i[:1], sub_block_space) for i in key1]
    key2 = linear_swap_forward(key1, key1+[35, 215, 221, 84, 79, 144], sub_block_size//2)
    key2 = [base_to_decimal(i[:4], 2**(sub_block_size//2) ) for i in key2]
    key3 = s_box_forward(key2, key1, sub_block_size)
    key3 = [base_to_decimal(i[:1], sub_block_space) for i in key3]
    processes = [0,3,1,2] + generate_processes([base_to_decimal(i, sub_block_space)
        for i in linear_swap_forward(key3, key2, sub_block_size//4)],
        {**{i:1 for i in (0,1)}, **{i:2 for i in (2,3)}}) # 0202XXXXXX X={0-1}
    cipher_bitblock_list = plain_bitblock_list
    keys = [key3]
    for process in processes:
        k = linear_shift_forward(keys[-1], keys[-1]+[process], sub_block_size)
        keys.append([base_to_decimal(i, sub_block_space) for i in k])

    for i, process in enumerate(processes):
        if process==0:
            cipher_bitblock_list = linear_shift_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            pass
        elif process==1:
            cipher_bitblock_list = reverse_subblock(cipher_bitblock_list)
            cipher_bitblock_list = linear_shift_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            pass
        elif process in (2,):
            cipher_bitblock_list = s_box_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            cipher_bitblock_list = linear_swap_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            pass
        elif process in (3,):
            cipher_bitblock_list = reverse_subblock(cipher_bitblock_list)
            cipher_bitblock_list = s_box_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            cipher_bitblock_list = linear_swap_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            pass
        elif process==5:
            cipher_bitblock_list = linear_swap_forward(cipher_bitblock_list, keys[i+1], sub_block_size)
            pass
    return cipher_bitblock_list



def decrypt_bitblock(cipher_bitblock_list, key_block_list, sub_block_size=8):
    sub_block_space = 2**sub_block_size
    key0 = key_expansion(key_block_list)
    key1 = linear_shift_forward([50524, 15702, 39651, 6295, 28348, 12071, 35661, 24141,
        668, 55643, 52851, 62390, 27290, 6457, 47093, 44059,
        43598, 34032, 50543, 5357, 14609, 24947, 28090, 1781,
        50795, 30647, 35077, 56306, 37512, 41124, 19279, 43475,
        52403, 730, 43513, 33090, 58988, 20101, 65008, 14513,
        38901, 20626, 62788, 13864, 44670, 12842, 6564, 26644,
        42699, 31359, 31127, 15088, 45717, 57093, 63113, 30010,
        15897, 13744, 405, 50, 1302, 15370, 4377, 8190][:max(256//sub_block_size, 16)],
        key0, sub_block_size*2)
    key1 = [base_to_decimal(i[:1], sub_block_space) for i in key1]
    key2 = linear_swap_forward(key1, key1+[35, 215, 221, 84, 79, 144], sub_block_size//2)
    key2 = [base_to_decimal(i[:4], 2**(sub_block_size//2) ) for i in key2]
    key3 = s_box_forward(key2, key1, sub_block_size)
    key3 = [base_to_decimal(i[:1], sub_block_space) for i in key3]
    processes = [0,3,1,2] + generate_processes([base_to_decimal(i, sub_block_space)
        for i in linear_swap_forward(key3, key2, sub_block_size//4)],
        {**{i:1 for i in (0,1)}, **{i:2 for i in (2,3)}}) # 0202XXXXXX X={0-3}
    plain_bitblock_list = cipher_bitblock_list
    keys = [key3]
    for process in processes:
        k = linear_shift_forward(keys[-1], keys[-1]+[process], sub_block_size)
        keys.append([base_to_decimal(i, sub_block_space) for i in k])

    for i, process in enumerate(processes[::-1]):
        if process==0:
            plain_bitblock_list = linear_shift_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            pass
        elif process==1:
            plain_bitblock_list = linear_shift_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            plain_bitblock_list = reverse_subblock(plain_bitblock_list)
            pass
        elif process in (2,):
            plain_bitblock_list = linear_swap_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            plain_bitblock_list = s_box_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            pass
        elif process in (3,):
            plain_bitblock_list = linear_swap_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            plain_bitblock_list = s_box_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            plain_bitblock_list = reverse_subblock(plain_bitblock_list)
            pass
        elif process==5:
            #plain_bitblock_list = linear_swap_backward(plain_bitblock_list, keys[-1-i], sub_block_size)
            pass
    return plain_bitblock_list




def encrypt_text(text, key, block_size=256, sub_block_size=8, text_char_blank=True,
        valid_text_chars = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
        valid_key_chars=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'):
    msg = text_to_block(text, block_size, text_char_blank, valid_text_chars)
    if key is None: cipher = [decimal_to_base(i, 2**sub_block_size) for i in msg]
    else:
        k = text_to_block(key, min(block_size, 16), True, valid_key_chars)
        cipher = encrypt_bitblock(msg, k, sub_block_size)
    cipher_hex_list = [int_list_to_hex_string(i, "-") for i in cipher]
    return ".".join(cipher_hex_list)

def decrypt_text(cipher, key, block_size=256, sub_block_size=8, text_char_blank=True,
        valid_text_chars = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
        valid_key_chars=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'):
    cipher_hex_list = cipher.split(".")
    cipher = [hex_string_to_int_list(i, "-") for i in cipher_hex_list]
    if key is None: msg = [base_to_decimal(i, 2**sub_block_size) for i in cipher]
    else:
        k = text_to_block(key, min(block_size, 16), True, valid_key_chars)
        msg = [base_to_decimal(i, 2**sub_block_size) for i in decrypt_bitblock(cipher, k, sub_block_size)]
    return block_to_text(msg, block_size, text_char_blank, valid_text_chars)



