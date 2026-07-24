"""
用户数据模型

使用 bcrypt 进行密码哈希存储
"""

import bcrypt
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class User:
    """用户数据模型"""

    username: str
    password_hash: str  # bcrypt hash
    role: str = "user"
    email: str = ""
    phone: str = ""
    balance: int = 0

    def to_dict(self, include_password=False) -> dict:
        """转换为字典，可选择是否包含密码哈希"""
        data = asdict(self)
        if not include_password:
            data.pop("password_hash", None)
        return data

    def get_safe_profile(self) -> dict:
        """获取安全的用户信息（不包含密码哈希）"""
        return {
            "username": self.username,
            "role": self.role,
            "email": self._mask_email(self.email) if self.email else "",
            "phone": self._mask_phone(self.phone) if self.phone else "",
            "balance": self.balance,
        }

    @staticmethod
    def _mask_email(email: str) -> str:
        """脱敏显示邮箱"""
        parts = email.split("@")
        if len(parts) == 2:
            name = parts[0]
            masked_name = name[:2] + "****" if len(name) > 2 else name[0] + "****"
            return f"{masked_name}@{parts[1]}"
        return email

    @staticmethod
    def _mask_phone(phone: str) -> str:
        """脱敏显示手机号"""
        if len(phone) == 11:
            return phone[:3] + "****" + phone[7:]
        return phone[:3] + "****" + phone[-4:] if len(phone) > 7 else phone


class UserDatabase:
    """用户数据库（内存版，演示用途）"""

    def __init__(self, bcrypt_rounds: int = 12):
        self._users: dict[str, User] = {}
        self.bcrypt_rounds = bcrypt_rounds

    def add_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        email: str = "",
        phone: str = "",
        balance: int = 0,
    ) -> User:
        """添加用户（密码自动哈希）"""
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=self.bcrypt_rounds),
        ).decode("utf-8")

        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            email=email,
            phone=phone,
            balance=balance,
        )
        self._users[username] = user
        return user

    def verify_password(self, username: str, password: str) -> Optional[User]:
        """验证用户密码"""
        user = self._users.get(username)
        if not user:
            return None

        if bcrypt.checkpw(
            password.encode("utf-8"),
            user.password_hash.encode("utf-8"),
        ):
            return user
        return None

    def get_user(self, username: str) -> Optional[User]:
        """获取用户对象"""
        return self._users.get(username)

    def user_exists(self, username: str) -> bool:
        """检查用户是否存在"""
        return username in self._users

    def update_password(self, username: str, new_password: str) -> bool:
        """直接更新用户密码，不验证原密码"""
        user = self._users.get(username)
        if not user:
            return False

        password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt(rounds=self.bcrypt_rounds),
        ).decode("utf-8")

        user.password_hash = password_hash
        return True

    def seed_default_users(self):
        """初始化默认用户"""
        # admin - 强密码
        self.add_user(
            username="admin",
            password="Admin@12345",
            role="admin",
            email="admin@example.com",
            phone="13800138000",
            balance=99999,
        )
        # alice - 强密码
        self.add_user(
            username="alice",
            password="Alice@2025",
            role="user",
            email="alice@example.com",
            phone="13900139001",
            balance=100,
        )
