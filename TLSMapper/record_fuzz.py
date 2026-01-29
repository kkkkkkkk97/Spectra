"""
TLS记录层Fuzzing工具
用于测试记录边界、MAC、Padding等

作者: Claude Code
日期: 2026-01-01
"""

import os
from random import randint, choice


class RecordFuzzer:
    """
    记录层fuzzing操作
    用于测试TLS记录层的各种边界情况和错误处理
    """

    def __init__(self, record_data=None):
        """
        初始化RecordFuzzer

        :param record_data: TLS记录数据 (bytes)
        """
        self.record_data = record_data

    def fuzz_length(self, record_data=None, strategy='invalid'):
        """
        C20: 测试关键消息必须在记录边界
        修改TLS记录的长度字段

        TLS记录格式: [Type(1) | Version(2) | Length(2) | Data]

        :param record_data: 记录数据，如果为None则使用self.record_data
        :param strategy: fuzzing策略
            - 'invalid': 修改长度字段使其不匹配实际数据
            - 'overflow': 长度字段超过最大记录大小
            - 'underflow': 长度字段为0或负数
            - 'misalign': 添加额外数据使消息跨越记录边界
        :return: fuzzed记录数据 (bytes)
        """
        data = record_data if record_data is not None else self.record_data

        if data is None or len(data) < 5:
            return data

        data = bytearray(data)

        if strategy == 'invalid':
            # 修改长度字段为错误值
            actual_length = len(data) - 5
            wrong_length = actual_length + randint(1, 100)
            data[3:5] = wrong_length.to_bytes(2, 'big')

        elif strategy == 'overflow':
            # 超过最大记录大小 (2^14 = 16384 bytes)
            data[3:5] = (16385).to_bytes(2, 'big')

        elif strategy == 'underflow':
            # 零长度
            data[3:5] = (0).to_bytes(2, 'big')

        elif strategy == 'misalign':
            # 添加额外数据使消息跨越记录边界
            extra_data = os.urandom(randint(1, 20))
            data = data + bytearray(extra_data)

        elif strategy == 'negative':
            # 负长度 (通过设置最高位)
            data[3:5] = (0x8000).to_bytes(2, 'big')

        return bytes(data)

    def _substitute_and_xor(self, data, substitutions, xors):
        """
        参考fuzz_tls的substitute_and_xor实现
        应用位置替换和XOR操作

        :param data: 数据
        :param substitutions: dict(int, int) - 位置到值的映射
        :param xors: dict(int, int) - 位置到XOR值的映射
        :return: 修改后的数据
        """
        data = bytearray(data)

        if substitutions is not None:
            for pos in substitutions:
                data[pos] = substitutions[pos]

        if xors is not None:
            for pos in xors:
                data[pos] ^= xors[pos]

        return bytes(data)

    def fuzz_mac(self, record_data=None, strategy='corrupt',
                 substitutions=None, xors=None):
        """
        测试MAC验证
        修改记录中的MAC字段

        :param record_data: 记录数据，如果为None则使用self.record_data
        :param strategy: fuzzing策略
            - 'corrupt': 修改MAC字段
            - 'truncate': 截断MAC
            - 'extend': 扩展MAC长度
            - 'zero': MAC全零
            - 'random': MAC完全随机化
            - 'custom': 使用substitutions/xors自定义修改
        :param substitutions: dict(int, int) - 位置到值的映射
        :param xors: dict(int, int) - 位置到XOR值的映射
        :return: fuzzed记录数据 (bytes)
        """
        data = record_data if record_data is not None else self.record_data

        if data is None or len(data) < 20:
            return data

        data = bytearray(data)

        if strategy == 'custom' and (substitutions or xors):
            # 使用fuzz_tls风格的自定义修改
            data = bytearray(self._substitute_and_xor(data, substitutions, xors))
        elif strategy == 'corrupt':
            # 假设MAC在最后16-32字节
            mac_offset = len(data) - 16
            for i in range(16):
                if mac_offset + i < len(data):
                    data[mac_offset + i] ^= 0xFF  # 翻转字节

        elif strategy == 'truncate':
            # 删除部分MAC
            data = data[:-8]

        elif strategy == 'extend':
            # 添加额外MAC字节
            data = data + os.urandom(16)

        elif strategy == 'zero':
            # MAC全零
            mac_offset = len(data) - 16
            for i in range(16):
                if mac_offset + i < len(data):
                    data[mac_offset + i] = 0

        elif strategy == 'random':
            # MAC完全随机化
            mac_offset = len(data) - 16
            for i in range(16):
                if mac_offset + i < len(data):
                    data[mac_offset + i] = randint(0, 255)

        return bytes(data)

    def fuzz_padding(self, record_data=None, strategy='invalid_length',
                     min_length=None, substitutions=None, xors=None):
        """
        测试Padding验证 (CBC模式)
        修改CBC模式的padding

        CBC Padding格式:
        - 最后一个字节是padding长度
        - 所有padding字节的值都应该等于padding长度

        :param record_data: 记录数据，如果为None则使用self.record_data
        :param strategy: fuzzing策略
            - 'invalid_length': 错误的padding长度字节
            - 'inconsistent': padding字节不一致
            - 'excessive': 超长padding
            - 'zero_padding': 零长度padding
            - 'custom': 使用substitutions/xors自定义修改
        :param min_length: 最小padding长度（包括长度字节）
        :param substitutions: dict(int, int) - 自定义位置修改
        :param xors: dict(int, int) - 自定义位置XOR
        :return: fuzzed记录数据 (bytes)
        """
        data = record_data if record_data is not None else self.record_data

        if data is None or len(data) < 16:
            return data

        data = bytearray(data)

        if strategy == 'custom' and (substitutions or xors):
            # 仅对padding部分应用修改
            pad_len = data[-1]
            if pad_len > 0 and pad_len < len(data):
                padding_start = len(data) - pad_len - 1
                padding = bytearray(data[padding_start:])
                padding = bytearray(self._substitute_and_xor(padding, substitutions, xors))
                data[padding_start:] = padding
        elif strategy == 'invalid_length':
            # 最后一个字节是padding长度，修改为错误值
            actual_pad_len = data[-1]
            data[-1] = (actual_pad_len + randint(1, 10)) % 256

        elif strategy == 'inconsistent':
            # padding长度正确，但padding字节值不一致
            pad_len = data[-1]
            for i in range(1, min(pad_len + 1, len(data))):
                data[-(i + 1)] = randint(0, 255)  # 随机值而非pad_len

        elif strategy == 'excessive':
            # 添加过多padding
            extra_padding = bytearray([0xFF] * 20)
            data = data + extra_padding
            data[-1] = 20  # 设置padding长度

        elif strategy == 'zero_padding':
            # 零长度padding（可能合法但边界情况）
            data[-1] = 0

        elif strategy == 'block_mismatch':
            # padding长度不是块大小的倍数
            data[-1] = 7  # 对于16字节块大小，7不对齐

        return bytes(data)

    def fuzz_record_type(self, record_data=None, invalid_type=99):
        """
        修改记录类型字段

        :param record_data: 记录数据
        :param invalid_type: 无效的记录类型值
        :return: fuzzed记录数据 (bytes)
        """
        data = record_data if record_data is not None else self.record_data

        if data is None or len(data) < 1:
            return data

        data = bytearray(data)
        data[0] = invalid_type  # 修改Type字段

        return bytes(data)

    def fuzz_record_version(self, record_data=None, invalid_version=(2, 0)):
        """
        修改记录版本字段

        :param record_data: 记录数据
        :param invalid_version: 无效的版本 (major, minor)
        :return: fuzzed记录数据 (bytes)
        """
        data = record_data if record_data is not None else self.record_data

        if data is None or len(data) < 3:
            return data

        data = bytearray(data)
        data[1] = invalid_version[0]  # Major version
        data[2] = invalid_version[1]  # Minor version

        return bytes(data)


def apply_fuzzer(data, fuzzer_fn, **kwargs):
    """
    辅助函数：应用fuzzer函数到数据

    :param data: 原始数据
    :param fuzzer_fn: fuzzer函数
    :param kwargs: fuzzer函数的参数
    :return: fuzzed数据
    """
    fuzzer = RecordFuzzer(data)
    return fuzzer_fn(data, **kwargs)
