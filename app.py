#coding=utf-8
import os
from flask import Flask, render_template, session, redirect, \
				  url_for, flash, current_app, request
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, \
						login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, \
					BooleanField, IntegerField, ValidationError
from wtforms.validators import Required, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


'''
Config
'''
basedir = os.path.abspath(os.path.dirname(__file__))

def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role)

app = Flask(__name__)
app.config.from_pyfile('db.cfg')
#app.config['SQLALCHEMY_DATABASE_URI'] =\
#	'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AdminPassword'] = 666666
app.config['SECRET_KEY'] = "this is a secret_key"
db = SQLAlchemy(app)
manager = Manager(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_shell_context))
login_manager = LoginManager(app)

login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message = u"To access this page, you need login in advance."


'''
Models
'''
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	users = db.relationship('User', backref='role', lazy='dynamic')

	@staticmethod
	def insert_roles():
		roles = ('Student','Admin')
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			db.session.add(role)
		db.session.commit()


	def __repr__(self):
		return '<Role %r>' %self.name

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	number = db.Column(db.SmallInteger, unique=True, index=True)
	username = db.Column(db.String(64), index=True)
	password = db.Column(db.String(128), default=123456)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	
	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		#新添加的用户，初始其角色为学生。
		if self.role is None:
			self.role = Role.query.filter_by(name='Student').first()

	def __repr__(self):
		return '<User %r>' %self.username

	#初次运行程序时生成初始管理员的静态方法
	@staticmethod
	def generate_admin():
		admin = Role.query.filter_by(name='Admin').first()
		u = User.query.filter_by(role=admin).first()
		if u is None:
			u = User(number = 000000, username = 'Admin',\
					 password = current_app.config['AdminPassword'],\
					 role = Role.query.filter_by(name='Admin').first())
			db.session.add(u)
		db.session.commit()

	def verify_password(self, password):
		return self.password == password

class Task(db.Model):
	__tablename__ = 'tasks'
	id = db.Column(db.Integer, primary_key=True)
	project_code = db.Column(db.Integer, primary_key=False,default=100)
	name = db.Column(db.String(64), unique=True)
	p0 = db.Column(db.String(64), unique=True)
	p1 = db.Column(db.String(64), unique=True)
	pp = db.Column(db.String(64), unique=True)

	#users = db.relationship('User', backref='role', lazy='dynamic')

	@staticmethod
	def insert_tasks():
		tasks = ('task_1','task_2','task_3')
		for r in tasks:
			task = Task.query.filter_by(name=r).first()
			if task is None:
				task = Task(name=r)
			db.session.add(task)
		db.session.commit()


	def __repr__(self):
		return  '%r' %self.name


'''
Forms
'''
#add by me
class TaskForm(FlaskForm):
	task_name = StringField(u'Name', validators=[Required()])
	#task_p0 = StringField(u'P0', validators=[Required()])
	#task_p1 = StringField(u'P1', validators=[Required()])
	#task_pp = StringField(u'PP', validators=[Required()])


	choices=[('on-going', 'on-going'), ('passed', 'passed'), ('failed', 'failed'), ('na', 'NA'), 
	('waved', 'Waved'), ('blocked', 'blocked'),('adddate', 'add date')]	
	task_p0 = SelectField(u'P0', choices=choices,validators=[Required()])
	task_p1 = SelectField(u'P1', choices=choices,validators=[Required()])
	task_pp = SelectField(u'PP', choices=choices,validators=[Required()])
	submit = SubmitField(u'Add')

	def validate(self):
		print("1.test:",super(TaskForm,self).validate())
		
		return True

		#return super(TaskForm,self).validate()




class LoginForm(FlaskForm):
	number = StringField(u'Account', validators=[Required()])
	password = PasswordField(u'Password', validators=[Required()])
	remember_me = BooleanField(u'Remember me')
	submit = SubmitField(u'login')


class SearchForm(FlaskForm):
	task_name = StringField(u'Task name', validators=[Required(message=u'Task name')])
	submit = SubmitField(u'Search')


class UserForm(FlaskForm):

	username = StringField(u'姓名', validators=[Required()])
	number = IntegerField(u'考号', validators=[Required(message=u'请输入数字')])
	submit = SubmitField(u'添加')



	def validate_number(self, field):
		if User.query.filter_by(number=field.data).first():
			raise ValidationError(u'此学生已存在，请检查考号！')


class EditForm(FlaskForm):
	def validate_date(self, field):
		if field.data == self.task_p0.data :
			raise ValidationError(u'此学生已存在，请检查考号！')
	#task_p0 = SelectField(u'P0', validators=[Required(),validate_date],choices=choices)

	task_name = StringField(u'Name', validators=[Required()])
	#task_p0 = StringField(u'P0', validators=[Required()])
	#task_p1 = StringField(u'P1', validators=[Required()])
	#task_pp = StringField(u'PP', validators=[Required()])
    
	choices=[('on-going', 'on-going'), ('passed', 'passed'), ('failed', 'failed'), 
	('na', 'NA'), ('waved', 'Waved'), ('blocked', 'blocked'),('adddate', 'add date')]
	task_p0 = SelectField(u'P0', validators=[Required()],choices=choices)
	task_p1 = SelectField(u'P1', choices=choices)
	task_pp = SelectField(u'PP', choices=choices)

	submit = SubmitField(u'Modify')

	def __init__(self, task, *args, **kargs):
		super(EditForm, self).__init__(*args, **kargs)
	#	self.task.choices = [(task.name, task.p0, task.p1, task.pp)
	#						 for task in Task.query.order_by(Task.name).all()]
		self.task = task

	def validate_number(self, field):
		if field.data != self.user.number and \
				User.query.filter_by(number=field.data).first():
			raise ValidationError(u'此学生已存在，请检查考号！')


'''
views
'''
@app.route('/task', methods=['GET', 'POST'])
@login_required
def task():
	li_id = request.args.get('id')
	print("id is:",li_id)
	form = SearchForm()
	Admin = Task.query.filter_by(name='Fixed').first()
	print("Admin is:",Admin," Admin.name is:",Admin.name)
	if form.validate_on_submit():
		#获得学生列表，其学号包含form中的数字
		tasks = Task.query.filter(Task.name.like \
								('%{}%'.format(form.task_name.data))).all()
	else:
		tasks = Task.query.order_by(Task.name.desc(), Task.name.asc()).all()
	return render_template('index.html', form=form, tasks=tasks, name=Admin.name,id=li_id)


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
	form = SearchForm()
	admin = Role.query.filter_by(name='Admin').first()
	if form.validate_on_submit():
		#获得学生列表，其学号包含form中的数字
		students = User.query.filter(User.number.like \
								('%{}%'.format(form.number.data))).all()
	else:
		students = User.query.order_by(User.role_id.desc(), User.number.asc()).all()
	return render_template('index.html', form=form, students=students, admin=admin)


#增加新考生
@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
	form = TaskForm()
	if form.validate_on_submit():
		task = Task(name=form.task_name.data,
					p0=form.task_p0.data,
					p1=form.task_p1.data,
					pp=form.task_pp.data)
		db.session.add(task)
		flash(u'Add sucessfully')
		return redirect(url_for('task'))
	return render_template('add_user.html', form=form)

	
#删除考生
@app.route('/remove_task/<int:id>', methods=['GET', 'POST'])
@login_required
def remove_task(id):
	task = Task.query.get_or_404(id)
	db.session.delete(task)
	flash(u'Delete this task sucessfully')
	return redirect(url_for('task'))


#修改考生资料
@app.route('/edit_task/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_task(id):
	task = Task.query.get_or_404(id)
	form = EditForm(task=task)
	if form.validate_on_submit():
		task.name = form.task_name.data
		task.p0 = form.task_p0.data
		task.p1 = form.task_p1.data
		task.pp = form.task_pp.data	
		db.session.add(task)
		flash(u'Has modified the task information')
		return redirect(url_for('task'))
	form.task_name.data = task.name
	form.task_p0.data = task.p0
	form.task_p1.data = task.p1
	form.task_pp.data = task.pp
	return render_template('edit_user.html', form=form, task=task)


#登录，系统只允许管理员登录
@app.route('/login', methods=['GET', 'POST'])
def login():
	form  = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(number=form.number.data).first()
		if user is not None and user.verify_password(form.password.data):
			if user.role != Role.query.filter_by(name='Admin').first():
				flash(u'系统只对管理员开放，请联系管理员获得权限！')
			else:
				login_user(user, form.remember_me.data)
				return redirect(url_for('task'))
		flash(u'用户名或密码错误！')
	return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash(u'SignOff sucessfully!')
	return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

#加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

'''
增加命令'python app.py init' 
以增加身份与初始管理员帐号
'''
@manager.command
def init():
	from app import Role, User
	Role.insert_roles()
	User.generate_admin()


if __name__=='__main__':
	manager.run()