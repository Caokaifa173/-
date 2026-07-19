"""
密码策略验证模块

强制实施强密码策略：
- 最小长度
- 至少一个大写字母
- 至少一个小写字母
- 至少一个数字
- 至少一个特殊字符
"""

import re


class PasswordPolicy:
    """密码策略验证"""

    def __init__(
        self,
        min_length=8,
        require_uppercase=True,
        require_lowercase=True,
        require_digit=True,
        require_special=True,
    ):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special

    def validate(self, password: str) -> tuple[bool, list[str]]:
        """
        验证密码强度

        返回:
            (是否通过, 错误信息列表)
        """
        errors = []

        if len(password) < self.min_length:
            errors.append(f"密码长度不能少于 {self.min_length} 位")

        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("密码必须包含至少一个大写字母")

        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("密码必须包含至少一个小写字母")

        if self.require_digit and not re.search(r"\d", password):
            errors.append("密码必须包含至少一个数字")

        if self.require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
            errors.append("密码必须包含至少一个特殊字符")

        return len(errors) == 0, errors

    def get_requirements_html(self) -> str:
        """生成密码要求说明 HTML"""
        parts = [f"至少 {self.min_length} 个字符"]
        if self.require_uppercase:
            parts.append("至少一个大写字母")
        if self.require_lowercase:
            parts.append("至少一个小写字母")
        if self.require_digit:
            parts.append("至少一个数字")
        if self.require_special:
            parts.append("至少一个特殊字符")
        return "，".join(parts)

    def get_requirements_text(self) -> str:
        """生成密码要求说明文本"""
        parts = [f"至少 {self.min_length} 位"]
        if self.require_uppercase:
            parts.append("大写字母")
        if self.require_lowercase:
            parts.append("小写字母")
        if self.require_digit:
            parts.append("数字")
        if self.require_special:
            parts.append("特殊字符")
        return ", ".join(parts)
