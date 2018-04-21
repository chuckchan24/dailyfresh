from django.contrib.auth.models import AbstractUser
from django.db import models

from Daily_Fresh import settings
from utils.models import BaseModel
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


class TestModel(BaseModel):
    """测试用"""

    name = models.CharField(max_length=20)


class User(BaseModel, AbstractUser):
    """用户模型类"""

    class Meta(object):
        # 指定表名
        db_table = 'df_user'

    def generate_active_token(self):
        """对字典数据{'confirm':用户id}加密，返回加密后的结果"""
        # 使用Serialize()生成序列化器，传入password and expire time
        serializer = Serializer(settings.SECRET_KEY, 3600)
        # dumps()生成user_id加密后的token, 传入封装user_id的字典
        token = serializer.dumps({'confirm': self.id})
        # 返回token byte解码成字符串
        return token.decode()


class Address(BaseModel):
    """用户地址"""
    receiver_name = models.CharField(max_length=20, verbose_name="收件人")
    receiver_mobile = models.CharField(max_length=11, verbose_name="联系电话")
    detail_addr = models.CharField(max_length=256, verbose_name="详细地址")
    zip_code = models.CharField(max_length=6, null=True, verbose_name="邮政编码")
    is_default = models.BooleanField(default=False, verbose_name='默认地址')
    user = models.ForeignKey(User, verbose_name="所属用户")

    class Meta:
        db_table = "df_address"
