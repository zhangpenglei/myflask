# -*- coding:utf-8 -*-
from flask_wtf import Form
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import  InputRequired,Length,Email,Regexp,EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(Form): # 登陆表格
    email=StringField('电子邮件', validators=[InputRequired(),Length(1,64),
                                          Email()])
    password = PasswordField('密码', validators =[InputRequired()])
    remember_me = BooleanField('保持我在线')
    submit = SubmitField('登陆')#检查按钮有没有提交

class RegistrationForm(Form):#注册表格
    email = StringField('Email/电子邮件', validators=[InputRequired(),Length(1, 64),
                                          Email()])

    username = StringField('Username/用户名', validators=[
        InputRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                                            'Usernames musthave only letters,'
                                            'numbers,dots or underscores')])
    password=PasswordField('Password/密码', validators=[
        InputRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password/确认密码', validators=[InputRequired()])
    submit = SubmitField('注册')


    #如果表单类中定义了以validate_ 开头且后面跟着字段名的方法，这个方法就和常规的验证函数一起调用

    def validate_email(self, field):  #检验数据库中是否已经包含了这个电子邮件
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("电子邮件已经存在")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise  ValidationError('用户名已经存在了')


class ChangePassword(Form):#修改密码
    old_password =PasswordField('旧的密码',validators=[InputRequired()])
    password=PasswordField('新的密码',validators=[InputRequired(),
                           EqualTo('password2',message='密码必须一样')])

    password2=PasswordField('确认你的新的密码', validators=[(InputRequired())])
    submit=SubmitField('更新你的密码')


class PasswordRestRequestForm(Form):#忘记密码,重置密码,email first
    email=StringField('电子邮件',validators=[InputRequired(),Length(1,64),
                                         Email()])
    submit=SubmitField('提交')
class PasswordReset(Form):#忘记密码,重置密码
    email=StringField('电子邮件', validators=[InputRequired(),Length(1,64),
                                           Email()])
    password=PasswordField('新的密码',validators=[InputRequired(),
                           EqualTo('password2', message='Passwords must match')])

    password2=PasswordField('确认密码',validators=[InputRequired()])
    submit=SubmitField('重置密码')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first()is None:
            raise ValidationError('无效的电子邮件地址')

