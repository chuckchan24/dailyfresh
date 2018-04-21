from django.conf.urls import url
from apps.users import views

urlpatterns = [
    # 视图函数
    # # 注册界面
    # url(r'^register$', views.register, name='register'),
    # # 后台注册逻辑
    # url(r'^do_register$', views.do_register, name='do_register'),

    # 类视图
    url(r'^register$', views.RegisterView.as_view(), name='register'),

    url(r'^register/(.+)$', views.ActiveView.as_view(), name='active'),
]
