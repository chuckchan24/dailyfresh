from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.generic import View
from django.core.urlresolvers import reverse

from apps.users.models import User


class IndexView(View):
    """主页类视图"""

    def get(self, request):
        """进入首页"""

        # 方式1：手动查询登录用户并显示
        # user_id = request.session.get('_auth_user_id')
        # user = User.objects.get(id=user_id)
        # context = {'user': user}
        # return render(request, 'index.html', context)

        # 方式2：使用django用户认证模块、直接显示
        # django会自动查询登录的用户对象，会保存到request对象
        # user = request.user  # request是django的login模块自动生成的
        return render(request, 'index.html')

