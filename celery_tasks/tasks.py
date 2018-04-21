# import os
# import django
#
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Daily_Fresh.settings")
# django.setup()

from django.core.mail import send_mail
from Daily_Fresh import settings
from celery import Celery

# 创建celery客户端
# 参数1：自定义的名称
# 参数2：保存任务用的broker
app = Celery('Daily_Fresh_Celery', broker='redis://127.0.0.1:6379/1')


@app.task
def send_active_email(username, email, token):
    """发送激活邮件"""

    subject = '天天生鲜激活邮件'  # 邮件标题，必须指定
    message = ''  # 正文
    from_email = settings.EMAIL_FROM  # 发件人
    recipient = [email]  # 收件人
    # 正文（带有html样式）
    html_message = ('<h2>尊敬的 %s, 感谢注册天天生鲜</h2>'
                    '<p>请点击此链接激活您的帐号: '
                    '<a href="http://127.0.0.1:8000/users/active/%s">'
                    'http://127.0.0.1:8000/users/active/%s</a>'
                    ) % (username, token, token)
    return send_mail(subject, message, from_email, recipient, html_message=html_message)

