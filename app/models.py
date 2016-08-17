# -*-coding:utf-8 -*-
from flask import request
from . import db
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin,AnonymousUserMixin #用户登陆
from .import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer#检验令牌
from flask import  current_app,url_for
from datetime import datetime
import hashlib    #head picture
from markdown import markdown
import bleach
from app.exceptions import ValidationError

class Permission:
    FOLLOW = 0X01#关注其他用户
    COMMENT = 0X02#在他人撰写的文章中发布评论
    WRITE_ARTICLES = 0x04#写原创文章
    MODERATE_COMMENTS = 0x08#查处他人发表的不当评论
    ADMINISTER = 0x80#管理网站


#加载用户的回调函数接收以 Unicode 字符串形式表示的用户标识符。如果能找到用户，这
# 个函数必须返回用户对象；否则应该返回 None。
@login_manager.user_loader
def load_user(user_id):#回调函数
    return User.query.get(int(user_id))

class Role (db.Model):#数据库的用户名
    __tablename__ = 'roles'  #表名
    id = db.Column(db.Integer, primary_key=True) #主键
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')#第一个参数表
# 明这个关系的另一端是哪个模型，backref 参数向 User 模型中添加一个 role 属性，从而定义反向关
# 系。这一属性可替代 role_id 访问 Role 模型，此时获取的是模型对象，而不是外键的值加入了 lazy = 'dynamic' 参数，从而禁止自动执行查询
# 系。这一属性可替代 role_id 访问 Role 模型，此时获取的是模型对象，而不是外键的值加入了 lazy = 'dynamic' 参数，从而禁止自动执行查询
    default=db.Column(db.Boolean,default=False,index=True)
    permissions=db.Column(db.Integer)

    def __repr__(self):  #输出一个更好看的格式
        return '<Role %r>' % self.name

    @staticmethod
    def insert_roles():
        roles = {
            'User':(Permission.FOLLOW|    #用户
                    Permission.COMMENT|
                    Permission.WRITE_ARTICLES,True),
            'Moderator':(Permission.FOLLOW|
                         Permission.COMMENT|
                         Permission.WRITE_ARTICLES|
                         Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)

        }
        for r in roles:
            role=Role.query.filter_by(name=r).first()
            if role is None:
                role=Role(name=r)
            role.permissions=roles[r][0]
            role.default=roles[r][1]
            db.session.add(role)
        db.session.commit()



class Post(db.Model):#博客文章
    __tablename__='posts'
    id=db.Column(db.Integer,primary_key=True)
    body=db.Column(db.Text)
    timestamp = db.Column(db.DateTime,index=True, default=datetime.utcnow())#时间戳
    author_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py


        seed()
        user_count=User.query.count()
        for i in range(count):
            u=User.query.offset(randint(0,user_count-1)).first()
            p=Post(body=forgery_py.lorem_ipsum.sentences(randint(1,5)),
                   timestamp=forgery_py.date.date(True),
                   author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']

        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))
        db.event.listen(Post.body, 'set', Post.on_changed_body)

    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id, _external=True),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author': url_for('api.get_user', id=self.author_id,
                              _external=True),
            'comments': url_for('api.get_post_comments', id=self.id,
                                _external=True),
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body = json_post.get('body')

        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
    primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
    primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):#UserMixin支持登陆
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64),unique=True, index=True) #unique这列不允许出现重复的值
    username = db.Column(db.String(64), unique=True, index=True)# index创造索引 提高查询效率
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    password_hash = db.Column(db.String(128))  # 密码散列哈西值长度
    confirmed=db.Column(db.Boolean,default=False)#检验令牌 默认为False
    name=db.Column(db.String(64))
    location=db.Column(db.String(64))#所在地
    about_me=db.Column(db.Text())#自我介绍
    member_since=db.Column(db.DateTime(),default=datetime.utcnow)#注册日期
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    def __init__ (self, **kwargs): #定义默认的用户角色
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email==current_app.config['FLASKY_ADMIN']:
                self.role=Role.query.filter_by( permissions=0xff).first()
            if self.role is None:
                self.role=Role.query.filter_by(default=True).first()
    #方法生成一个令牌，有效期默认为一小时。
    def generate_confirmation_token(self, expiration=3600):#3600为有效期1个小时
        s = Serializer(current_app.config['SECRET_KEY'], expiration)#Serializer生成具有过期时间的 JSON Web 签名
        return s.dumps({'confirm': self.id})    #dumps() 方法为指定的数据生成一个加密签名，然后再对数据和签名进行序列化，生成令
# 牌字符串



   # confirm() 方法检验令牌，如果检验通过，则把新添加的 confirmed 属性设为 True。
    def confirm(self, token):
        s=Serializer(current_app.config['SECRET_KEY'])
        try:
            data=s.loads(token)#检验签名和过期时间
        except:
            return False
        if data.get('confirm')!= self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True



    @property   #负责把一个方法变成属性调用的：
    def password(self):
        raise AttributeError('passworld is not a  readable attribute')

    @password.setter
    def password(self, password):  # 设置密码
        self.password_hash = generate_password_hash(password)#生成哈希值

    def verify_password(self, password):  # 检验密码的正确性
        return check_password_hash(self.password_hash,password)


    def can(self,permissions):#请求和赋予角色这两种权限之间进行位与操作
        return self.role is not None and \
               (self.role.permissions&permissions)==permissions

    def is_adminstrator(self):#先检查用户
        return self.can(Permission.ADMINISTER)




    def ping(self):#但用户每次访问网站后，这个值都会被刷新
        self.last_see=datetime.utcnow()
        db.session.add(self)

    def __repr__(self):
        return '<User %r>' % self.username


    @staticmethod
    def generate_fake(count=100):#生成虚拟用户和博客文章
        from sqlalchemy.exc import IntegrityError
        from random import  seed
        import forgery_py


        seed()
        for i in range(count):
            u=User(email=forgery_py.internet.email_address(),
                   username=forgery_py.internet.user_name(True),
                   password=forgery_py.lorem_ipsum.word(),
                   confirmed=True,
                   name=forgery_py.name.full_name(),
                   location=forgery_py.address.city(),
                   about_me=forgery_py.lorem_ipsum.sentence(),
                   member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def follow(self, user):
        if not self.is_following(user):
            f= Follow(follower=self, followed=user)

            db.session.add(f)

    def is_following(self, user):
        return self.followed.filter_by(
            followed_id = user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id, _external=True),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts': url_for('api.get_user_posts', id=self.id, _external=True),
            'followed_posts': url_for('api.get_user_followed_posts',
                                      id=self.id, _external=True),
            'post_count': self.posts.count()
        }
        return json_user



class AnonymousUser(AnonymousUserMixin):#这样程序不用先检查用户是否登录就能自由调用 current_user.can() 和
#current_user.is_administrator()。


    def can(self, permissions):
        return False
    def is_administrator(self):
        return False
login_manager.anonymous_user = AnonymousUser

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
                tags=allowed_tags, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_changed_body)





