from django.conf.urls import url
from apps.users import views

urlpatterns = [
    # 注册界面
    url(r'^register$', views.register),

    # 后台注册逻辑
    url(r'^do_register$', views.do_register, name='do_register'),
]