#-*- coding: utf-8 -*-
#!/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role,Post,Permission
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand#数据库迁移

#实例化
app = create_app(os.getenv('FLASK_CONFIG') or 'default')#有环境写好的配置或者默认的配置
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():#注册了程序、数据库实例以及模型，因此这些对象能直接导入 shel
    return dict(app=app, db=db, User=User, Role=Role,Post=Post,Permission=Permission)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@manager.command#单元测试
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

def deploy():
    """Run deployment tasks."""
    from flask.ext.migrate import upgrade
    from app.models import Role, User

    # migrate database to latest revision
    upgrade()

    # create user roles
    Role.insert_roles()

    # create self-follows for all users
    User.add_self_follows()


if __name__ == '__main__':

    manager.run()
