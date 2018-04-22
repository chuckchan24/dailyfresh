from django.conf.urls import url
from apps.users import views

urlpatterns = [
    # 视图函数
    # # 注册界面
    # url(r'^register$', views.register, name='register'),
    # # 后台注册逻辑
    # url(r'^do_register$', views.do_register, name='do_register'),

    # 注册界面的类视图
    url(r'^register$', views.RegisterView.as_view(), name='register'),  # 注册用户
    url(r'^register/(.+)$', views.ActiveView.as_view(), name='active'),  # 激活用户

    # 登录界面的类视图
    url(r'^login$', views.LoginView.as_view(), name='login'),  # 用户登录
    # 注销类视图
    url(r'^logout$', views.LogoutView.as_view(), name='logout'),  # 用户登录


]
