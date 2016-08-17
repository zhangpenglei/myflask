# -*- coding:utf-8 -*-
from flask_wtf import Form
from wtforms import StringField, SubmitField,validators,TextAreaField,BooleanField,SelectField\


from wtforms.validators import InputRequired,Length,Email,Regexp,ValidationError
from ..models import Role, User
from  flask_pagedown.fields import PageDownField

class NameForm(Form):
    name = StringField('What is your name?', validators=[InputRequired()])
    submit = SubmitField('Submit')


class EditProfileForm(Form):
    name=StringField('真实的姓名',validators=[Length(0,64)])
    location=StringField('地址',validators=[Length(0,64)])
    about_me=TextAreaField('自我介绍')
    submit=SubmitField('提交')

class EditProfileAdminForm(Form):
    email=StringField('电子邮件',validators=[InputRequired(),Length(1,64),Email()])
    username=StringField('用户名',validators=[InputRequired(),Length(1,64),
                                                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                       '用户名必须是字母,数字,下划线')])
    confirmed=BooleanField('确认')
    role=SelectField('Role',coerce=int)
    name=StringField('真实的姓名',validators=[Length(0,64)])
    location = StringField('地址', validators=[Length(0, 64)])
    about_me = TextAreaField('自我介绍')
    submit = SubmitField('提交')

    def __init__(self,user,*args,**kwargs):
        super(EditProfileAdminForm, self).__init__(*args,**kwargs)
        self.role.choices=[(role.id,role.name)
                           for role in Role.query.order_by(Role.name).all()]
        self.user=user


    def validate_email(self,field):##检验数据库中是否已经包含了这个电子邮件
        if field.data!=self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class PostForm(Form):
    body=PageDownField("waht's on your mind?", validators=[InputRequired()])
    submit = SubmitField("Submit")

class CommentForm(Form):
    body = StringField('Enter your comment', validators=[InputRequired()])
    submit = SubmitField('Submit')
