from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length

import constants


class LoginForm(FlaskForm):
    username = StringField('Email or Phone', validators=[
        DataRequired(),
        Length(min=5, max=100),
        # Regexp(r'^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$|^(\d{3}-\d{3}-\d{4})$',
        #        message='Invalid email or phone number')
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ManagerForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=5, max=50)
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    hired_date = DateField('Hired Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EmployeeForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=5, max=50)
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    department = SelectField('Department', choices=constants.department_choices, validators=[DataRequired()])
    designation = SelectField('Designation', choices=constants.designation_choices, validators=[DataRequired()])
    manager = SelectField('Manager', validators=[DataRequired()], choices=str)
    hired_date = DateField('Hired Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Submit')


class PermissionForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=5, max=50)
    ])
    submit = SubmitField('Submit')


class RoleForm(FlaskForm):
    name = StringField('Role Name', validators=[
        DataRequired(),
        Length(min=4, max=50)
    ])
    permissions = SelectMultipleField('Permissions', choices=[], coerce=str)
    submit = SubmitField('Submit')
