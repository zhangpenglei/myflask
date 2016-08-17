# -*- coding:utf-8 -*-
from flask import  render_template,redirect,request,url_for,flash
from . import auth
from flask_login import  login_required,login_user,current_user#保护陆游
from ..models import   User
from .forms import LoginForm
from flask_login import logout_user,login_required#退出界面
from .forms import LoginForm, RegistrationForm,ChangePassword,PasswordRestRequestForm,PasswordReset#注册界面
from .. import db#数据库
from ..email import send_email


#解决UnicodeDecodeError: ‘ascii’ codec can’t decode byte 0xe5 in position 108: ordinal not in range(128
#这个书上没有 貌似到了python3就没关系了 坑死的代码
import sys
reload(sys)
sys.setdefaultencoding('utf-8')



#处理程序中过滤未确认的账户
@auth.before_app_request
def before_request():
    # 用户已登录
    if current_user.is_authenticated:
        current_user.ping()
        if  not current_user.confirmed \
                and request.endpoint[:5] != 'auth.':

            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')#unconfirmed
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET','POST'])#登陆
def login():
    form = LoginForm()   # 表格
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next')or url_for('main.index'))
        flash('无效的帐号或者密码')

    return render_template('auth/login.html', form=form)



@auth.route('/logout')
@login_required
def logout():
    logout_user()#清除登陆的信息
    flash('你已经退出了')
    return redirect(url_for('main.index'))


@auth.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                  username=form.username.data,
                  password=form.password.data)


        db.session.add(user)
        db.session.commit()
        token=user.generate_confirmation_token()
        send_email(user.email,'Confirm your Account',
                   'auth/email/confirm',user=user,token=token)
        flash('A confirmation email has been sent to you by email.')


        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):              #确认用户的账户
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.route('/confirm')
@login_required
def resend_confirmation():  #重新发送账户确认邮件
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change-password',methods=['GET','POST'])
@login_required
def change_password():
    form=ChangePassword()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password=form.password.data
            db.session.add(current_user)
            flash('Your password has been updated')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password')
    return render_template("auth/change_password.html", form=form)

@auth.route('/reset',methods=['GET','POST'])
def password_reset_request():
    if not current_user.is_anonymous:#判断当前用户是否是匿名用户
        return redirect(url_for('main.index'))
    form=PasswordRestRequestForm()
    if  form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user:
            token=user.generate_confirmation_token()##方法生成一个令牌，有效期默认为一小时。
            send_email(user.email,'重置密码','auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
        flash('一个邮件已经发送到你的邮箱了')
        return redirect(url_for('auth.login '))
    return render_template('auth/reset_password.html', form=form)

@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordReset()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)



