from random import choice, randint
import struct
import re
fuzz_operator = {
    0: 'truncating_operator',
    1: 'removing_operator',
    2: 'duplicating_operator',
    3: 'contentfuzz_operator',
    4: 'randomstring_operator',
    5: 'flip_bit_operator',
    6: 'flip_byte_operator',
    7: 'insert_random_data_operator',
    8: 'replace_random_byte_operator',
    9: 'swap_adjacent_bytes_operator',
    10: 'repeat_random_block_operator',
    11: 'delete_random_block_operator',
    12: 'full_nullify_operator',
    13: 'partial_nullify_operator',
    14: 'zero_fill_operator'
}

def randomstring(length=4):
    a = "".join([choice("0123456789ABCDEF") for _ in range(2 * length)])
    if length == 1:
        return struct.pack('B', int(a, 16))
    elif length == 2:
        return struct.pack('H', int(a, 16))
    elif length == 4:
        return struct.pack('L', int(a, 16))
    elif length == 8:
        return struct.pack('Q', int(a, 16))
    elif length == 0:
        return b''
    return bytes.fromhex(a)

def get_r(keyword, pkt_len):
    if keyword == 'truncating_operator':
        return {'truncating_operator': randint(40, pkt_len)}
    elif keyword == 'removing_operator':
        start = randint(1, pkt_len)
        length = randint(1, 10)
        return {'removing_operator': [start, length]}
    elif keyword == 'duplicating_operator':
        start = randint(1, pkt_len)
        length = randint(2, 10)
        return {'duplicating_operator': [start, length]}
    elif keyword == 'contentfuzz_operator':
        start = randint(0, pkt_len - 4)  # Ensure there's enough space for 4 bytes
        data = randomstring(choice([1, 2, 4, 8]))
        length = choice([1, 2, 4, 8])
        return {'contentfuzz_operator': [start, data, length]}
    elif keyword == 'randomstring_operator':
        start = randint(0, pkt_len)
        data = randomstring(randint(0, 16))
        length = randint(1, 10)
        return {'randomstring_operator': [start, data, length]}
    elif keyword == 'flip_bit_operator':
        index = randint(0, pkt_len - 1)
        bit_position = randint(0, 7)
        return {'flip_bit_operator': [index, bit_position]}
    elif keyword == 'flip_byte_operator':
        index = randint(0, pkt_len - 1)
        return {'flip_byte_operator': index}
    elif keyword == 'insert_random_data_operator':
        index = randint(0, pkt_len)
        data_length = randint(1, 16)
        data = randomstring(data_length)
        return {'insert_random_data_operator': [index, data]}
    elif keyword == 'replace_random_byte_operator':
        index = randint(0, pkt_len - 1)
        new_byte = choice(range(256))
        return {'replace_random_byte_operator': [index, new_byte]}
    elif keyword == 'swap_adjacent_bytes_operator':
        if pkt_len < 2:
            return {}
        index = randint(0, pkt_len - 2)
        return {'swap_adjacent_bytes_operator': index}
    elif keyword == 'repeat_random_block_operator':
        if pkt_len < 2:
            return {}
        start = randint(0, pkt_len - 2)
        block_size = randint(1, min(4, pkt_len - start))
        repeat_count = randint(2, 10)
        return {'repeat_random_block_operator': [start, block_size, repeat_count]}
    elif keyword == 'delete_random_block_operator':
        start = randint(0, pkt_len - 1)
        block_size = randint(1, min(10, pkt_len - start))
        return {'delete_random_block_operator': [start, block_size]}
    if keyword == 'full_nullify_operator':
        return {'full_nullify_operator': True}
    elif keyword == 'partial_nullify_operator':
        if pkt_len == 0:
            return {'partial_nullify_operator': (0, 0)}
        start = randint(0, pkt_len - 1)
        length = randint(1, pkt_len - start)
        return {'partial_nullify_operator': (start, length)}
    elif keyword == 'zero_fill_operator':
        if pkt_len == 0:
            return {'zero_fill_operator': (0, 0)}
        start = randint(0, pkt_len - 1)
        length = randint(1, pkt_len - start)
        return {'zero_fill_operator': (start, length)}
    
    raise ValueError(f"Unknown keyword: {keyword}")

class RandomFuzz:
    def __init__(self, packet=None):
        self.packet = packet or b''

    def apply_operator(self, operator_name):
        if not hasattr(self, operator_name):
            raise ValueError(f"No such operator: {operator_name}")
        method = getattr(self, operator_name)
        key = get_r(operator_name, len(self.packet))
        return method(key)

    def truncating_operator(self, key):
        cur_len = key['truncating_operator']
        return self.packet[:cur_len]

    def removing_operator(self, key):
        start, length = key['removing_operator']
        return self.packet[:start] + self.packet[start + length:]

    def duplicating_operator(self, key):
        start, length = key['duplicating_operator']
        segment = self.packet[start:start + length]
        return self.packet[:start] + segment + segment + self.packet[start + length:]

    def contentfuzz_operator(self, key):
        start, data, length = key['contentfuzz_operator']
        forward = self.packet[:start]
        end = self.packet[start + length:]
        return forward + data + end

    def randomstring_operator(self, key):
        start, data, length = key['randomstring_operator']
        forward = self.packet[:start]
        end = self.packet[start + length:]
        return forward + data + end

    def flip_bit_operator(self, key):
        index, bit_position = key['flip_bit_operator']
        byte_value = self.packet[index]
        flipped_byte = byte_value ^ (1 << bit_position)
        return self.packet[:index] + bytes([flipped_byte]) + self.packet[index + 1:]

    def flip_byte_operator(self, key):
        index = key['flip_byte_operator']
        byte_value = self.packet[index]
        flipped_byte = ~byte_value & 0xFF
        return self.packet[:index] + bytes([flipped_byte]) + self.packet[index + 1:]

    def insert_random_data_operator(self, key):
        index, data = key['insert_random_data_operator']
        return self.packet[:index] + data + self.packet[index:]

    def replace_random_byte_operator(self, key):
        index, new_byte = key['replace_random_byte_operator']
        return self.packet[:index] + bytes([new_byte]) + self.packet[index + 1:]

    def swap_adjacent_bytes_operator(self, key):
        index = key['swap_adjacent_bytes_operator']
        return self.packet[:index] + self.packet[index + 1:index + 2] + self.packet[index:index + 1] + self.packet[index + 2:]

    def repeat_random_block_operator(self, key):
        start, block_size, repeat_count = key['repeat_random_block_operator']
        block = self.packet[start:start + block_size]
        repeated_block = block * repeat_count
        return self.packet[:start] + repeated_block + self.packet[start + block_size:]

    def delete_random_block_operator(self, key):
        start, block_size = key['delete_random_block_operator']
        return self.packet[:start] + self.packet[start + block_size:]
    
    def full_nullify_operator(self, key):
        """
        直接将整个 packet 置空
        """
        return b'' if isinstance(self.packet, bytes) else ''

    def partial_nullify_operator(self, key):
        """删除 packet 的一段（长度变短）"""
        start, length = key['partial_nullify_operator']
        return self.packet[:start] + self.packet[start + length:]

    def zero_fill_operator(self, key):
        """将 packet 的一段用 0x00 覆盖（长度不变）"""
        start, length = key['zero_fill_operator']
        packet = bytearray(self.packet)
        packet[start:start + length] = b'\x00' * length
        return bytes(packet)
    

    def tuple_fuzz_operator(self):
        # mode = choice(['random', 'negative', 'overflow', 'nonnumeric', 'empty', 'big'])
        mode = choice(['random', 'big','default'])

        if mode == 'random':
            a = randint(0, 999)
            b = randint(0, 999)
            return (a, b)
        elif mode == 'default':
            a = randint(0, 32)
            b = randint(0, 32)
            return (a, b)
        # elif mode == 'negative':
        #     a = -randint(1, 100)
        #     b = -randint(1, 100)
        #     return (a, b)
        # elif mode == 'overflow':
        #     a = randint(1 << 16, 1 << 24)
        #     b = randint(1 << 16, 1 << 24)
        #     return (a, b)
        # elif mode == 'nonnumeric':
        #     a = choice(['A', '!', 'foo'])
        #     b = choice(['B', '%', 'bar'])
        #     return (a, b)
        # elif mode == 'empty':
        #     return tuple()
        # elif mode == 'big':
        #     a = randint(0, 1 << 32)
        #     b = randint(0, 1 << 32)
        #     return (a, b)
        elif mode == 'big':
            a = randint(0, 255)
            b = randint(0, 255)
            return (a, b)
        elif mode == 'small':
            a = randint(0, 8)
            b = randint(0, 8)
            return (a, b)

