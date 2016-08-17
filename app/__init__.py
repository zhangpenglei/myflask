# -*- coding:utf-8 -*-
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown


bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()#实例化
login_manager.session_protection = 'Strong'     # None Basic 设为 'strong' 时， Flask-Login 会记录客户端 IP
# 地址和浏览器的用户代理信息， 如果发现异动就登出用户
login_manager.login_view = 'auth.login'     # login_view 属性设置登录页面
# 的端点
pagedown=PageDown()


def create_app(config_name):#创建app
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    pagedown.init_app(app)


    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint    # auth 蓝本要在 create_app() 工厂函数中附加到程序上
    app.register_blueprint(auth_blueprint,url_prefix='/auth')
    # 注册后蓝本中定义的所有路由都会加上指定的前缀， 即这个例子中的 /auth
    login_manager.init_app(app) # 使用指定的标识符加载用户
    #
    from .api_1_0 import api as api_1_0_blueprint
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')
    return app

