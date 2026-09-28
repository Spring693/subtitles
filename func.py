#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
随机密码生成器 (Random Password Generator)
==========================================

功能特性：
    1. 支持多种密码生成模式（随机、易记、PIN码、口令短语）
    2. 可自定义密码长度、字符集
    3. 密码强度评估
    4. 批量生成密码
    5. 排除易混淆字符
    6. 支持配置保存与加载
    7. 命令行接口 (CLI)
    8. 密码熵值计算
    9. 生成日志记录
    10. 密码历史去重

作者: Password Generator
版本: 1.0.0
"""

import os
import sys
import json
import math
import random
import string
import secrets
import hashlib
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ============================================================================
# 常量定义
# ============================================================================

# 字符集
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AMBIGUOUS_CHARS = "Il1O0o"

# 易记密码用的单词表（示例）
WORD_LIST = [
    "apple", "banana", "cherry", "dragon", "eagle", "forest", "guitar",
    "hunter", "island", "jungle", "knight", "lemon", "mountain", "night",
    "ocean", "pencil", "queen", "river", "sunset", "tiger", "umbrella",
    "violet", "winter", "xenon", "yellow", "zebra", "anchor", "bridge",
    "castle", "dolphin", "engine", "falcon", "garden", "harbor", "igloo",
    "jacket", "kitten", "lantern", "meadow", "nectar", "orchid", "puzzle",
    "quartz", "rocket", "silver", "tunnel", "urban", "valley", "wizard",
    "crystal", "ember", "flame", "glacier", "horizon", "ivory", "jewel",
    "karma", "legend", "mirror", "nebula", "oasis", "phoenix", "quest",
    "raven", "shadow", "thunder", "unity", "voyage", "whisper", "zenith",
    "amber", "blossom", "cascade", "dusk", "echo", "frost", "glow",
    "harmony", "infinite", "jasper", "kaleidoscope", "luminous", "mystic",
]

# 默认配置
DEFAULT_CONFIG = {
    "length": 16,
    "use_lowercase": True,
    "use_uppercase": True,
    "use_digits": True,
    "use_symbols": True,
    "exclude_ambiguous": False,
    "min_digits": 1,
    "min_symbols": 1,
    "min_uppercase": 1,
    "min_lowercase": 1,
    "count": 1,
}


# ============================================================================
# 日志配置
# ============================================================================

def setup_logger(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    """配置日志记录器"""
    logger = logging.getLogger("PasswordGenerator")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # 避免重复添加 handler
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 控制台输出
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件输出
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except IOError as e:
            logger.warning(f"无法创建日志文件: {e}")

    return logger


# ============================================================================
# 数据类
# ============================================================================

@dataclass
class PasswordConfig:
    """密码生成配置"""
    length: int = 16
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    min_lowercase: int = 1
    min_uppercase: int = 1
    min_digits: int = 1
    min_symbols: int = 1

    def to_dict(self) -> Dict:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "PasswordConfig":
        """从字典创建"""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def get_charset(self) -> str:
        """获取有效字符集"""
        charset = ""
        if self.use_lowercase:
            charset += LOWERCASE
        if self.use_uppercase:
            charset += UPPERCASE
        if self.use_digits:
            charset += DIGITS
        if self.use_symbols:
            charset += SYMBOLS

        if self.exclude_ambiguous:
            charset = "".join(c for c in charset if c not in AMBIGUOUS_CHARS)

        return charset

    def validate(self) -> Tuple[bool, str]:
        """验证配置是否有效"""
        if self.length < 4:
            return False, "密码长度至少为 4"
        if self.length > 256:
            return False, "密码长度不能超过 256"

        if not any([self.use_lowercase, self.use_uppercase,
                    self.use_digits, self.use_symbols]):
            return False, "至少需要选择一种字符类型"

        min_total = (self.min_lowercase + self.min_uppercase +
                     self.min_digits + self.min_symbols)
        if min_total > self.length:
            return False, f"最小字符要求总数 ({min_total}) 超过密码长度 ({self.length})"

        if self.use_lowercase and self.min_lowercase < 0:
            return False, "小写字母最小数量不能为负"
        if self.use_uppercase and self.min_uppercase < 0:
            return False, "大写字母最小数量不能为负"
        if self.use_digits and self.min_digits < 0:
            return False, "数字最小数量不能为负"
        if self.use_symbols and self.min_symbols < 0:
            return False, "符号最小数量不能为负"

        return True, "配置有效"


@dataclass
class PasswordResult:
    """密码生成结果"""
    password: str
    entropy: float
    strength: str
    score: int
    length: int
    charset_size: int
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# 密码生成器核心类
# ============================================================================

class PasswordGenerator:
    """密码生成器"""

    def __init__(self, config: Optional[PasswordConfig] = None,
                 logger: Optional[logging.Logger] = None):
        self.config = config or PasswordConfig()
        self.logger = logger or setup_logger()
        self._history: Set[str] = set()

        valid, msg = self.config.validate()
        if not valid:
            raise ValueError(f"配置无效: {msg}")

    # ------------------------------------------------------------------
    # 基础生成方法
    # ------------------------------------------------------------------

    def _get_charset(self) -> str:
        """获取字符集"""
        return self.config.get_charset()

    def _random_char(self, charset: str) -> str:
        """使用加密安全的随机源生成单个字符"""
        return secrets.choice(charset)

    def _shuffle(self, items: List[str]) -> List[str]:
        """使用加密安全的随机源打乱列表"""
        # secrets 模块没有 shuffle，使用 SystemRandom
        rng = random.SystemRandom()
        rng.shuffle(items)
        return items

    # ------------------------------------------------------------------
    # 密码生成策略
    # ------------------------------------------------------------------

    def generate_random(self) -> str:
        """生成完全随机的密码"""
        charset = self._get_charset()
        if not charset:
            raise ValueError("字符集为空")

        password_chars = []
        cfg = self.config

        # 满足最小字符数要求
        if cfg.use_lowercase:
            for _ in range(cfg.min_lowercase):
                password_chars.append(self._random_char(LOWERCASE))
        if cfg.use_uppercase:
            for _ in range(cfg.min_uppercase):
                password_chars.append(self._random_char(UPPERCASE))
        if cfg.use_digits:
            for _ in range(cfg.min_digits):
                password_chars.append(self._random_char(DIGITS))
        if cfg.use_symbols:
            for _ in range(cfg.min_symbols):
                password_chars.append(self._random_char(SYMBOLS))

        # 填充剩余长度
        while len(password_chars) < cfg.length:
            password_chars.append(self._random_char(charset))

        # 打乱顺序
        self._shuffle(password_chars)
        return "".join(password_chars[:cfg.length])

    def generate_memorable(self, word_count: int = 4,
                           separator: str = "-",
                           add_numbers: bool = True) -> str:
        """生成易记密码（由单词组成）"""
        if word_count < 2:
            word_count = 2
        if word_count > 10:
            word_count = 10

        words = []
        for _ in range(word_count):
            word = secrets.choice(WORD_LIST)
            # 随机大小写
            if secrets.randbelow(2):
                word = word.capitalize()
            words.append(word)

        password = separator.join(words)

        if add_numbers:
            # 添加随机数字
            num = secrets.randbelow(9000) + 1000
            password += separator + str(num)

        return password

    def generate_pin(self, length: int = 6) -> str:
        """生成纯数字 PIN 码"""
        if length < 3:
            length = 3
        if length > 20:
            length = 20
        return "".join(secrets.choice(DIGITS) for _ in range(length))

    def generate_passphrase(self, word_count: int = 5,
                            separator: str = " ",
                            capitalize: bool = True) -> str:
        """生成口令短语"""
        if word_count < 2:
            word_count = 2
        if word_count > 12:
            word_count = 12

        words = []
        for _ in range(word_count):
            word = secrets.choice(WORD_LIST)
            if capitalize:
                word = word.capitalize()
            words.append(word)

        return separator.join(words)

    def generate_uuid_like(self) -> str:
        """生成 UUID 风格的密码"""
        import uuid
        return str(uuid.uuid4()).replace("-", "")

    def generate_hex(self, length: int = 32) -> str:
        """生成十六进制密码"""
        if length < 4:
            length = 4
        if length > 128:
            length = 128
        return secrets.token_hex(length // 2)[:length]

    def generate_base64(self, length: int = 24) -> str:
        """生成 Base64 风格密码"""
        import base64
        if length < 4:
            length = 4
        if length > 128:
            length = 128
        raw = secrets.token_bytes((length * 3) // 4 + 3)
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
        # 移除填充
        encoded = encoded.rstrip("=")
        return encoded[:length]

    # ------------------------------------------------------------------
    # 批量生成
    # ------------------------------------------------------------------

    def generate_batch(self, count: int,
                       unique: bool = True,
                       strategy: str = "random") -> List[str]:
        """批量生成密码"""
        if count < 1:
            count = 1
        if count > 10000:
            raise ValueError("批量生成数量不能超过 10000")

        passwords = []
        attempts = 0
        max_attempts = count * 10

        while len(passwords) < count and attempts < max_attempts:
            attempts += 1

            if strategy == "random":
                pwd = self.generate_random()
            elif strategy == "memorable":
                pwd = self.generate_memorable()
            elif strategy == "pin":
                pwd = self.generate_pin()
            elif strategy == "passphrase":
                pwd = self.generate_passphrase()
            elif strategy == "hex":
                pwd = self.generate_hex()
            elif strategy == "base64":
                pwd = self.generate_base64()
            else:
                pwd = self.generate_random()

            if unique and pwd in self._history:
                continue

            self._history.add(pwd)
            passwords.append(pwd)

        if len(passwords) < count:
            self.logger.warning(
                f"仅生成了 {len(passwords)}/{count} 个唯一密码"
            )

        return passwords

    # ------------------------------------------------------------------
    # 强度评估
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_entropy(password: str, charset_size: int) -> float:
        """计算密码熵值（比特）"""
        if charset_size <= 1:
            return 0.0
        return len(password) * math.log2(charset_size)

    @staticmethod
    def evaluate_strength(password: str) -> Tuple[str, int, float]:
        """
        评估密码强度
        返回: (强度等级, 分数 0-100, 熵值)
        """
        if not password:
            return "非常弱", 0, 0.0

        length = len(password)
        score = 0

        # 长度评分 (最多 40 分)
        if length >= 16:
            score += 40
        elif length >= 12:
            score += 30
        elif length >= 8:
            score += 20
        elif length >= 6:
            score += 10
        else:
            score += length * 2

        # 字符类型评分 (最多 40 分)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in SYMBOLS or not c.isalnum() for c in password)

        type_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += type_count * 10

        # 复杂度评分 (最多 20 分)
        unique_chars = len(set(password))
        unique_ratio = unique_chars / length if length > 0 else 0
        score += int(unique_ratio * 20)

        # 扣分项
        # 纯数字
        if password.isdigit():
            score -= 15
        # 纯字母
        if password.isalpha():
            score -= 10
        # 重复字符
        if unique_chars <= 3:
            score -= 15

        score = max(0, min(100, score))

        # 熵值
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += len(SYMBOLS)
        entropy = PasswordGenerator.calculate_entropy(password, charset_size)

        # 强度等级
        if score >= 85 and entropy >= 80:
            strength = "非常强"
        elif score >= 70 and entropy >= 60:
            strength = "强"
        elif score >= 50 and entropy >= 40:
            strength = "中等"
        elif score >= 30:
            strength = "弱"
        else:
            strength = "非常弱"

        return strength, score, entropy

    # ------------------------------------------------------------------
    # 完整生成流程
    # ------------------------------------------------------------------

    def generate(self, strategy: str = "random") -> PasswordResult:
        """生成密码并返回完整结果"""
        if strategy == "random":
            password = self.generate_random()
        elif strategy == "memorable":
            password = self.generate_memorable()
        elif strategy == "pin":
            password = self.generate_pin()
        elif strategy == "passphrase":
            password = self.generate_passphrase()
        elif strategy == "hex":
            password = self.generate_hex()
        elif strategy == "base64":
            password = self.generate_base64()
        else:
            raise ValueError(f"未知的生成策略: {strategy}")

        strength, score, entropy = self.evaluate_strength(password)
        charset_size = len(self._get_charset())

        return PasswordResult(
            password=password,
            entropy=round(entropy, 2),
            strength=strength,
            score=score,
            length=len(password),
            charset_size=charset_size,
        )


# ============================================================================
# 配置管理
# ============================================================================

class ConfigManager:
    """配置管理器"""

    DEFAULT_PATH = Path.home() / ".password_generator.json"

    def __init__(self, path: Optional[Path] = None):
        self.path = path or self.DEFAULT_PATH

    def load(self) -> Dict:
        """加载配置"""
        if not self.path.exists():
            return dict(DEFAULT_CONFIG)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 合并默认配置
            merged = dict(DEFAULT_CONFIG)
            merged.update(data)
            return merged
        except (json.JSONDecodeError, IOError):
            return dict(DEFAULT_CONFIG)

    def save(self, config: Dict) -> bool:
        """保存配置"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except IOError:
            return False

    def reset(self) -> bool:
        """重置配置"""
        try:
            if self.path.exists():
                self.path.unlink()
            return True
        except IOError:
            return False


# ============================================================================
# 密码历史记录
# ============================================================================

class HistoryManager:
    """密码历史管理器（仅存储哈希，不存储明文）"""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (Path.home() / ".password_history.json")
        self.hashes: List[str] = []
        self._load()

    def _load(self):
        """加载历史"""
        if not self.path.exists():
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.hashes = data.get("hashes", [])
        except (json.JSONDecodeError, IOError):
            self.hashes = []

    def _save(self):
        """保存历史"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"hashes": self.hashes[-1000:]}, f, indent=2)
        except IOError:
            pass

    @staticmethod
    def _hash(password: str) -> str:
        """对密码进行哈希"""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def add(self, password: str):
        """添加密码哈希"""
        h = self._hash(password)
        if h not in self.hashes:
            self.hashes.append(h)
            self._save()

    def contains(self, password: str) -> bool:
        """检查密码是否已存在"""
        return self._hash(password) in self.hashes

    def clear(self):
        """清空历史"""
        self.hashes = []
        self._save()


# ============================================================================
# 输出格式化
# ============================================================================

class OutputFormatter:
    """输出格式化器"""

    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    @classmethod
    def colorize(cls, text: str, color: str, use_color: bool = True) -> str:
        """给文本着色"""
        if not use_color:
            return text
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['reset']}"

    @classmethod
    def strength_color(cls, strength: str) -> str:
        """根据强度返回颜色"""
        mapping = {
            "非常强": "green",
            "强": "green",
            "中等": "yellow",
            "弱": "red",
            "非常弱": "red",
        }
        return mapping.get(strength, "white")

    @classmethod
    def format_result(cls, result: PasswordResult,
                      use_color: bool = True,
                      show_details: bool = True) -> str:
        """格式化单个结果"""
        lines = []
        pwd = cls.colorize(result.password, "cyan", use_color)
        lines.append(f"密码: {pwd}")

        if show_details:
            color = cls.strength_color(result.strength)
            strength = cls.colorize(result.strength, color, use_color)
            lines.append(f"  长度: {result.length}")
            lines.append(f"  强度: {strength} (评分: {result.score}/100)")
            lines.append(f"  熵值: {result.entropy} bits")
            lines.append(f"  字符集大小: {result.charset_size}")

        return "\n".join(lines)

    @classmethod
    def format_batch(cls, results: List[PasswordResult],
                     use_color: bool = True,
                     show_details: bool = False) -> str:
        """格式化批量结果"""
        lines = []
        for i, result in enumerate(results, 1):
            if show_details:
                lines.append(f"[{i}]")
                lines.append(cls.format_result(result, use_color, True))
                lines.append("")
            else:
                pwd = cls.colorize(result.password, "cyan", use_color)
                color = cls.strength_color(result.strength)
                strength = cls.colorize(result.strength, color, use_color)
                lines.append(f"[{i:3d}] {pwd}  ({strength})")
        return "\n".join(lines)


# ============================================================================
# 命令行界面
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="password-generator",
        description="随机密码生成器 - 生成安全、随机的密码",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                             生成一个默认密码
  %(prog)s -l 20                       生成 20 位密码
  %(prog)s -n 5                        批量生成 5 个密码
  %(prog)s -l 12 --no-symbols          生成 12 位不含符号的密码
  %(prog)s --strategy memorable        生成易记密码
  %(prog)s --strategy pin -l 6         生成 6 位 PIN 码
  %(prog)s --strategy passphrase       生成口令短语
  %(prog)s --exclude-ambiguous         排除易混淆字符
  %(prog)s --json                      以 JSON 格式输出
  %(prog)s --save-config               保存当前配置
        """
    )

    # 基本参数
    parser.add_argument("-l", "--length", type=int,
                        help="密码长度 (默认: 16)")
    parser.add_argument("-n", "--count", type=int,
                        help="生成密码数量 (默认: 1)")

    # 字符集选项
    charset_group = parser.add_argument_group("字符集选项")
    charset_group.add_argument("--no-lowercase", action="store_true",
                               help="不使用小写字母")
    charset_group.add_argument("--no-uppercase", action="store_true",
                               help="不使用大写字母")
    charset_group.add_argument("--no-digits", action="store_true",
                               help="不使用数字")
    charset_group.add_argument("--no-symbols", action="store_true",
                               help="不使用符号")
    charset_group.add_argument("--exclude-ambiguous", action="store_true",
                               help="排除易混淆字符 (如 0/O, 1/l/I)")

    # 最小字符要求
    min_group = parser.add_argument_group("最小字符要求")
    min_group.add_argument("--min-digits", type=int,
                           help="最少数字数量")
    min_group.add_argument("--min-symbols", type=int,
                           help="最少符号数量")
    min_group.add_argument("--min-uppercase", type=int,
                           help="最少大写字母数量")
    min_group.add_argument("--min-lowercase", type=int,
                           help="最少小写字母数量")

    # 生成策略
    parser.add_argument("--strategy", choices=[
        "random", "memorable", "pin", "passphrase", "hex", "base64"
    ], default="random", help="生成策略 (默认: random)")

    # 输出选项
    output_group = parser.add_argument_group("输出选项")
    output_group.add_argument("--json", action="store_true",
                              help="以 JSON 格式输出")
    output_group.add_argument("--no-color", action="store_true",
                              help="禁用彩色输出")
    output_group.add_argument("--details", action="store_true",
                              help="显示详细信息")
    output_group.add_argument("--quiet", "-q", action="store_true",
                              help="仅输出密码")

    # 配置管理
    config_group = parser.add_argument_group("配置管理")
    config_group.add_argument("--save-config", action="store_true",
                              help="保存当前配置")
    config_group.add_argument("--reset-config", action="store_true",
                              help="重置配置为默认值")
    config_group.add_argument("--config-file", type=str,
                              help="指定配置文件路径")

    # 其他
    parser.add_argument("--log-file", type=str,
                        help="日志文件路径")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="详细输出")
    parser.add_argument("--version", action="version",
                        version="%(prog)s 1.0.0")

    return parser


def build_config_from_args(args: argparse.Namespace,
                           base_config: Dict) -> PasswordConfig:
    """从命令行参数构建配置"""
    config = dict(base_config)

    if args.length is not None:
        config["length"] = args.length
    if args.no_lowercase:
        config["use_lowercase"] = False
    if args.no_uppercase:
        config["use_uppercase"] = False
    if args.no_digits:
        config["use_digits"] = False
    if args.no_symbols:
        config["use_symbols"] = False
    if args.exclude_ambiguous:
        config["exclude_ambiguous"] = True
    if args.min_digits is not None:
        config["min_digits"] = args.min_digits
    if args.min_symbols is not None:
        config["min_symbols"] = args.min_symbols
    if args.min_uppercase is not None:
        config["min_uppercase"] = args.min_uppercase
    if args.min_lowercase is not None:
        config["min_lowercase"] = args.min_lowercase

    return PasswordConfig.from_dict(config)


def output_json(results: List[PasswordResult]):
    """以 JSON 格式输出结果"""
    data = []
    for r in results:
        data.append({
            "password": r.password,
            "length": r.length,
            "entropy": r.entropy,
            "strength": r.strength,
            "score": r.score,
            "charset_size": r.charset_size,
            "generated_at": r.generated_at,
        })
    print(json.dumps(data, ensure_ascii=False, indent=2))


def output_plain(results: List[PasswordResult], quiet: bool = False):
    """纯文本输出"""
    for r in results:
        print(r.password)


def main(argv: Optional[List[str]] = None) -> int:
    """主函数"""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # 设置日志
    logger = setup_logger(args.log_file, args.verbose)

    # 配置管理
    config_path = Path(args.config_file) if args.config_file else None
    config_manager = ConfigManager(config_path)

    # 重置配置
    if args.reset_config:
        if config_manager.reset():
            print("配置已重置为默认值")
        else:
            print("重置配置失败", file=sys.stderr)
            return 1
        return 0

    # 加载配置
    base_config = config_manager.load()

    # 构建密码配置
    try:
        password_config = build_config_from_args(args, base_config)
    except Exception as e:
        print(f"配置错误: {e}", file=sys.stderr)
        return 1

    # 验证配置
    valid, msg = password_config.validate()
    if not valid:
        print(f"配置无效: {msg}", file=sys.stderr)
        return 1

    # 保存配置
    if args.save_config:
        save_data = password_config.to_dict()
        if config_manager.save(save_data):
            print(f"配置已保存到: {config_manager.path}")
        else:
            print("保存配置失败", file=sys.stderr)
            return 1

    # 创建生成器
    try:
        generator = PasswordGenerator(password_config, logger)
    except ValueError as e:
        print(f"初始化失败: {e}", file=sys.stderr)
        return 1

    # 生成密码
    count = args.count or base_config.get("count", 1)
    try:
        if count == 1:
            results = [generator.generate(args.strategy)]
        else:
            passwords = generator.generate_batch(count, strategy=args.strategy)
            results = []
            for pwd in passwords:
                strength, score, entropy = generator.evaluate_strength(pwd)
                results.append(PasswordResult(
                    password=pwd,
                    entropy=round(entropy, 2),
                    strength=strength,
                    score=score,
                    length=len(pwd),
                    charset_size=len(password_config.get_charset()),
                ))
    except Exception as e:
        print(f"生成失败: {e}", file=sys.stderr)
        return 1

    # 输出结果
    use_color = not args.no_color and sys.stdout.isatty()

    if args.json:
        output_json(results)
    elif args.quiet:
        output_plain(results, quiet=True)
    elif count == 1:
        print(OutputFormatter.format_result(
            results[0], use_color, show_details=True
        ))
    else:
        print(OutputFormatter.format_batch(
            results, use_color, show_details=args.details
        ))

    return 0


# ============================================================================
# 交互式模式
# ============================================================================

def interactive_mode():
    """交互式菜单模式"""
    config_manager = ConfigManager()
    base_config = config_manager.load()
    config = PasswordConfig.from_dict(base_config)

    print("=" * 60)
    print("          随机密码生成器 - 交互式模式")
    print("=" * 60)

    while True:
        print()
        print("当前配置:")
        print(f"  密码长度: {config.length}")
        print(f"  使用小写: {'是' if config.use_lowercase else '否'}")
        print(f"  使用大写: {'是' if config.use_uppercase else '否'}")
        print(f"  使用数字: {'是' if config.use_digits else '否'}")
        print(f"  使用符号: {'是' if config.use_symbols else '否'}")
        print(f"  排除易混淆: {'是' if config.exclude_ambiguous else '否'}")
        print()
        print("操作菜单:")
        print("  1. 生成密码")
        print("  2. 修改密码长度")
        print("  3. 切换小写字母")
        print("  4. 切换大写字母")
        print("  5. 切换数字")
        print("  6. 切换符号")
        print("  7. 切换排除易混淆字符")
        print("  8. 保存配置")
        print("  9. 批量生成")
        print("  0. 退出")
        print()

        try:
            choice = input("请选择操作: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见！")
            break

        if choice == "1":
            valid, msg = config.validate()
            if not valid:
                print(f"配置错误: {msg}")
                continue
            gen = PasswordGenerator(config)
            result = gen.generate()
            print()
            print(OutputFormatter.format_result(result, use_color=True))

        elif choice == "2":
            try:
                length = int(input("请输入密码长度 (4-256): ").strip())
                if 4 <= length <= 256:
                    config.length = length
                    print(f"密码长度已设置为: {length}")
                else:
                    print("长度必须在 4-256 之间")
            except ValueError:
                print("输入无效")

        elif choice == "3":
            config.use_lowercase = not config.use_lowercase
            print(f"小写字母: {'启用' if config.use_lowercase else '禁用'}")

        elif choice == "4":
            config.use_uppercase = not config.use_uppercase
            print(f"大写字母: {'启用' if config.use_uppercase else '禁用'}")

        elif choice == "5":
            config.use_digits = not config.use_digits
            print(f"数字: {'启用' if config.use_digits else '禁用'}")

        elif choice == "6":
            config.use_symbols = not config.use_symbols
            print(f"符号: {'启用' if config.use_symbols else '禁用'}")

        elif choice == "7":
            config.exclude_ambiguous = not config.exclude_ambiguous
            print(f"排除易混淆: {'启用' if config.exclude_ambiguous else '禁用'}")

        elif choice == "8":
            if config_manager.save(config.to_dict()):
                print("配置已保存")
            else:
                print("保存失败")

        elif choice == "9":
            try:
                count = int(input("生成数量 (1-100): ").strip())
                count = max(1, min(100, count))
                valid, msg = config.validate()
                if not valid:
                    print(f"配置错误: {msg}")
                    continue
                gen = PasswordGenerator(config)
                passwords = gen.generate_batch(count)
                print()
                for i, pwd in enumerate(passwords, 1):
                    strength, score, _ = gen.evaluate_strength(pwd)
                    print(f"[{i:3d}] {pwd}  ({strength})")
            except ValueError:
                print("输入无效")

        elif choice == "0":
            print("再见！")
            break

        else:
            print("无效的选择")


# ============================================================================
# 程序入口
# ============================================================================

if __name__ == "__main__":
    # 如果没有命令行参数，进入交互模式
    if len(sys.argv) == 1:
        try:
            interactive_mode()
        except KeyboardInterrupt:
            print("\n\n程序已中断")
            sys.exit(0)
    else:
        sys.exit(main())