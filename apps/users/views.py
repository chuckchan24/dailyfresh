from django.shortcuts import render
from django.http import HttpResponse
import re
from apps.users.models import User
from django.views.generic import View
from Daily_Fresh import settings
from django.core.mail import send_mail
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from celery_tasks import tasks


class RegisterView(View):
    """注册类视图"""

    def get(self, request):
        """用户注册界面"""
        return render(request, 'register.html')

    def post(self, request):
        """后台注册逻辑"""
        # 获取注册请求参数
        user_dict = request.POST
        username = user_dict.get('username')
        password = user_dict.get('password')
        password_confirm = user_dict.get('password2')
        email = user_dict.get('email')
        allow = user_dict.get('allow')  # 是否勾选

        # 校验注册请求参数
        # 逻辑判断 0 0.0 '' None [] () {}  -> False
        # all: 所有的变量都为True, all函数才返回True, 否则返回False
        if not all([username, password, password_confirm, email]):
            return render(request, 'register.html', {'message': '参数不完整'})

        # 判断两次输入的密码是否正确
        if password != password_confirm:
            return render(request, 'register.html', {'message': '两次输入的密码不一致'})

        # 判断是否勾选了用户协议
        if allow != 'on':
            return render(request, 'register.html', {'message': '请先同意用户协议'})

        # 判断邮箱格式是否正确
        if not re.match('^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'message': '邮箱格式不正确'})

        # 保存用户注册信息
        # create_user: 是django提供的方法, 会对密码进行加密后再保存到数据库
        user = None
        try:
            user = User.objects.create_user(username=username,
                                            password=password,
                                            email=email)  # type:User
            user.is_active = False
            user.save()
        except IntegrityError as e:  # IntegrityError:
            print(e)
            return render(request, 'register.html', {'message': '用户名已存在'})

        # 发送激活邮件
        # 获取token对象
        token = user.generate_active_token()
        # 同步发送会阻塞
        # self.send_active_email(username, email, token)
        # 使用celery异步发送不会阻塞
        # 会保存方法名到redis数据库
        tasks.send_active_email.delay(username, email, token)

        return HttpResponse('进入登录界面')

    @staticmethod
    def send_active_email(username, email, token):
        """发送激活邮件"""

        subject = '天天生鲜激活邮件'  # 邮件标题，必须指定
        message = ''                # 正文
        from_email = settings.EMAIL_FROM  # 发件人
        recipient = [email]  #收件人
        # 正文（带有html样式）
        html_message = ('<h2>尊敬的 %s, 感谢注册天天生鲜</h2>'
                        '<p>请点击此链接激活您的帐号: '
                        '<a href="http://127.0.0.1:8000/users/active/%s">'
                        'http://127.0.0.1:8000/users/active/%s</a>'
                        ) % (username, token, token)
        return send_mail(subject, message, from_email, recipient, html_message=html_message)


class ActiveView(View):
    """用户激活"""

    def get(self, request, token):
        """
        用户激活
        :param request:
        :param token: 对字典进行加密后得到的字符串
        :return:
        """
        try:
            # 解密token
            s = Serializer(settings.SECRET_KEY, 3600*2)
            # 字符串 --> bytes
            # dict_data = s.loads(token.encode())
            dict_data = s.loads(token)

        except SignatureExpired:
            return HttpResponse('激活链接已经失效')

        # 获取用户id
        user_id = dict_data.get('confirm')
        # 修改字段为已激活
        User.objects.filter(id=user_id).update(is_active=True)

        # 激活成功进入登录界面
        return HttpResponse('激活成功,进入登录界面')
