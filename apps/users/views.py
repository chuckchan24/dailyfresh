from django.shortcuts import render
from django.http import HttpResponse
import re
from apps.users.models import User


def register(request):
    """用户注册界面"""
    return render(request, 'register.html')


def do_register(request):
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
    try:
        User.objects.create_user(username=username,
                                password=password,
                                email=email)
    except Exception as e:  # IntegrityError:
        print(e)
        return render(request, 'register.html', {'message': '用户名已存在'})

    # todo: 发送确认邮件

    return HttpResponse('进入登录界面')
