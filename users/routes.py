import csv
import io
import json
import gridfs
from bson import ObjectId

import openpyxl
from flask import Blueprint, render_template, request, url_for, redirect, flash, session, Response, send_file

from flask_login import login_user, current_user, logout_user

import constants
from config import mongo
from users import utils
from users.forms import LoginForm, ManagerForm, EmployeeForm, PermissionForm, RoleForm
from users.user import User


login_bp = Blueprint(
    'login_bp', __name__,
    template_folder='templates'
)

export_bp = Blueprint(
    'export_bp', __name__,
    url_prefix="/export",
    template_folder='templates'
)

roles_bp = Blueprint(
    'roles_bp', __name__,
    url_prefix="/role",
    template_folder='templates'
)

permissions_bp = Blueprint(
    'permissions_bp', __name__,
    url_prefix="/permission",
    template_folder='users/templates'
)

admin_bp = Blueprint(
    'admin_bp', __name__,
    url_prefix="/admin",
    template_folder='users/templates'
)

employee_bp = Blueprint(
    'employee_bp', __name__,
    url_prefix="/employee",
    template_folder='users/templates'
)

manager_bp = Blueprint(
    'manager_bp', __name__,
    url_prefix="/manager",
    template_folder='users/templates'
)


@admin_bp.route('/dashboard', methods=('GET', 'POST'))
@utils.role_required(["admin"])
def admin_dashboard():
    employees = session.get('filtered_employees')
    if employees is None:
        employees = utils.get_employees()
    session.pop('filtered_employees', None)
    return render_template(
        'admin_dashboard.html',
        managers=utils.get_managers(),
        employees=employees,
        permissions=utils.get_permissions(),
        roles=utils.get_roles(),
        department_choices=constants.department_choices,
        designation_choices=constants.designation_choices)


@roles_bp.route('/create', methods=('GET', 'POST'))
@utils.role_required(["admin"])
def create_role():
    form = RoleForm()
    form.permissions.choices = [(permission.get('_id'), permission.get('name')) for permission in utils.get_permissions()]
    if request.method == 'POST':
        name = form.name.data
        existing_role = mongo.db.roles.find_one({'name': name})
        if existing_role:
            flash('Role name must be unique.', 'danger')
        else:
            permissions_ids = form.permissions.data
            mongo.db.roles.insert_one({'name': name, 'permissions_ids': [ObjectId(each) for each in permissions_ids]})
            return redirect(url_for('admin_bp.admin_dashboard'))
    return render_template('role_create.html', form=form)


@roles_bp.route('/delete/<role_id>', methods=('GET', 'POST'))
@utils.role_required(["admin"])
def delete_role(role_id):
    role_id = ObjectId(role_id)
    mongo.db.roles.delete_one({'_id': role_id})
    mongo.db.users.update_many(
        {"role_id": role_id},
        {"$set": {"role_id": None}}
    )
    return redirect(url_for('admin_bp.admin_dashboard'))


@permissions_bp.route('/create', methods=('GET', 'POST'))
@utils.role_required(["admin"])
def create_permission():
    form = PermissionForm()
    if form.validate_on_submit():
        name = request.form['name']
        existing_permission = mongo.db.permissions.find_one({'name': name})
        if existing_permission:
            flash('Permission name must be unique.', 'danger')
        else:
            mongo.db.permissions.insert_one({'name': name})
            return redirect(url_for('admin_bp.admin_dashboard'))
    return render_template('permission_create.html', form=form)


@permissions_bp.route('/delete/<permission_id>', methods=('GET', 'POST'))
@utils.role_required(["admin"])
def delete_permission(permission_id):
    mongo.db.roles.update_many({}, {"$pull": {"permissions_ids": permission_id}})
    mongo.db.permissions.delete_one({'_id': ObjectId(permission_id)})
    return redirect(url_for('admin_bp.admin_dashboard'))


@manager_bp.route('/dashboard', methods=('GET', 'POST'))   # Focus here
@utils.role_required(["manager"])
def manager_dashboard():
    employees = session.get('filtered_employees')
    if employees is None:
        employees = utils.get_employees()
    session.pop('filtered_employees', None)
    return render_template(
        'manager_dashboard.html',
        employees=employees, department_choices=constants.department_choices, designation_choices=constants.designation_choices)


@manager_bp.route('/create', methods=('GET', 'POST'))   # Focus here
@utils.role_required(["admin"])
def create_manager():
    if not utils.get_manager_role():
        flash("You need to first create a role with 'manager'", 'danger')
        if current_user.role == "manager":
            return redirect(url_for('manager_bp.manager_dashboard'))
        return redirect(url_for('admin_bp.admin_dashboard'))
    form = ManagerForm()
    if form.validate_on_submit():
        if utils.is_email_exists(request.form['email']):
            flash('Email must be unique.', 'danger')
        elif utils.is_phonenumber_exists(request.form['phone']):
            flash('Phone number must be unique.', 'danger')
        else:
            mongo.db.users.insert_one(
                {'name': request.form['name'], 'email': request.form['email'], 'phone': request.form['phone'],
                 'password': request.form['password'], 'hired_date': request.form['hired_date'],
                 'role_id': utils.get_manager_role()['_id']})
            if current_user.role == "manager":
                return redirect(url_for('manager_bp.manager_dashboard'))
            return redirect(url_for('admin_bp.admin_dashboard'))
    return render_template('manager_create.html', form=form)


@employee_bp.route('/dashboard', methods=('GET', 'POST'))
@utils.role_required(["employee"])
def employee_dashboard():
    user_id = current_user.id
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({"_id": user_id})
    if user:
        user['_id'] = str(user['_id'])
        user['manager'] = mongo.db.users.find_one({"_id": user["manager"]})["name"]
        return render_template('employee_dashboard.html', user=user)
    flash('Employee details not found.', 'danger')
    return redirect(url_for('login_bp.login'))


@employee_bp.route('/detail/<employee_id>', methods=('GET', 'POST'))
@utils.role_required(["admin", "manager"])
def employee_detail(employee_id):
    form = EmployeeForm()
    form.manager.choices = [(manager.get('_id'), manager.get('name')) for manager in utils.get_managers()]
    if ObjectId.is_valid(employee_id):
        employee = mongo.db.users.find_one({'_id': ObjectId(employee_id)})
        if employee:
            return render_template('employee_detail.html', form=form, employee=employee)
    flash('Employee details not found.', 'danger')
    return redirect(url_for('login_bp.login'))


@employee_bp.route('/create', methods=('GET', 'POST'))   # Focus here
@utils.role_required(["admin", "manager"])
def create_employee():
    if not utils.get_employee_role():
        flash("You need to first create a role with 'employee'", 'danger')
        if current_user.role == "manager":
            return redirect(url_for('manager_bp.manager_dashboard'))
        return redirect(url_for('admin_bp.admin_dashboard'))
    form = EmployeeForm()
    form.manager.choices = [(manager.get('_id'), manager.get('name')) for manager in utils.get_managers()]
    if form.validate_on_submit():
        if utils.is_email_exists(request.form['email']):
            flash('Email must be unique.', 'danger')
        elif utils.is_phonenumber_exists(request.form['phone']):
            flash('Phone number must be unique.', 'danger')
        else:
            mongo.db.users.insert_one(
                {'name': request.form['name'], 'email': request.form['email'], 'phone': request.form['phone'],
                 'password': request.form['password'], 'designation': request.form['designation'], 'department': request.form['department'],
                 'manager': ObjectId(request.form['manager']), 'hired_date': request.form['hired_date'],
                 'role_id': utils.get_employee_role()['_id']})
            if current_user.role == "manager":
                return redirect(url_for('manager_bp.manager_dashboard'))
            return redirect(url_for('admin_bp.admin_dashboard'))
    return render_template('employee_create.html', form=form)


@employee_bp.route('/edit/<employee_id>', methods=('GET', 'POST'))   # Focus here
@utils.role_required(["admin", "manager"])
def edit_employee(employee_id):
    form = EmployeeForm()
    form.manager.choices = [(manager.get('_id'), manager.get('name')) for manager in utils.get_managers()]
    if request.method == 'POST':
        new_data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'phone': request.form['phone'],
            'designation': request.form['designation'],
            'department': request.form['department'],
            'manager': ObjectId(request.form['manager']),
            'hired_date': request.form['hired_date']
        }
        mongo.db.users.update_one({'_id': ObjectId(employee_id)}, {'$set': new_data})
        if current_user.role == "manager":
            return redirect(url_for('manager_bp.manager_dashboard'))
        return redirect(url_for('admin_bp.admin_dashboard'))
    else:
        employee = mongo.db.users.find_one({'_id': ObjectId(employee_id)})
        return render_template('employee_edit.html', form=form, employee=employee)


@employee_bp.route('/delete/<employee_id>', methods=('GET', 'POST'))   # Focus here
@utils.role_required(["admin", "manager"])
def delete_employee(employee_id):
    mongo.db.users.delete_one({'_id': ObjectId(employee_id)})
    return redirect(url_for('manager_bp.manager_dashboard'))


@employee_bp.route('/filter_employees', methods=['POST'])
@utils.role_required(["admin", "manager"])
def filter_employees():
    designation = request.form.get('designation')
    department = request.form.get('department')
    employees = utils.get_employees()
    filtered_employees = [employee for employee in employees if
                          employee['designation'] == designation and employee['department'] == department]
    for employee in filtered_employees:
        employee['_id'] = str(employee['_id'])
        employee['manager'] = str(employee['manager'])
        employee['role_id'] = str(employee['role_id'])
    session['filtered_employees'] = filtered_employees
    if current_user.role == "manager":
        return redirect(url_for('manager_bp.manager_dashboard'))
    return redirect(url_for('admin_bp.admin_dashboard'))


@employee_bp.route('/search_employees', methods=['GET', 'POST'])
@utils.role_required(["admin", "manager"])
def search_employees():
    search_query = request.form.get('search')
    employees = utils.get_employees()
    if search_query:
        employees = [employee for employee in employees if
                     (search_query in employee.get('name', '') or search_query in employee.get('phone', '') or
                      search_query in employee.get('email', ''))]
        if current_user.role == "manager":
            return render_template(
                'manager_dashboard.html',
                employees=employees,
                department_choices=constants.department_choices,
                designation_choices=constants.designation_choices)
        return render_template(
            'admin_dashboard.html',
            managers=utils.get_managers(),
            employees=employees,
            permissions=utils.get_permissions(),
            roles=utils.get_roles(),
            department_choices=constants.department_choices,
            designation_choices=constants.designation_choices)
    if current_user.role == "manager":
        return redirect(url_for('manager_bp.manager_dashboard'))
    return redirect(url_for('admin_bp.admin_dashboard'))


@export_bp.route('/<export_type>', methods=['GET', 'POST'])
@utils.role_required(["admin", "manager"])
def export(export_type):
    employees = utils.get_employees()
    fs = gridfs.GridFS(mongo.db)
    headers = ['Name', 'Email', 'Phone', 'Manager', 'Designation', 'Department']
    if export_type == 'csv':
        pass
    elif export_type == 'json':
        pass
    elif export_type == 'xlsx':
        pass


@login_bp.route('/', methods=('GET', 'POST'))   # Focus here
def login():
    logout()
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user_data = mongo.db.users.find_one({"$or": [{"email": username}, {"phone": username}]})
        if user_data and user_data['password'] == password:
            user_role = mongo.db.roles.find_one({"_id": user_data.get('role_id')})
            if not user_data.get('role_id') or not user_role:
                flash('Login failed. No Role Assigned.', 'danger')
                return render_template('login.html', form=form)
            user_role = mongo.db.roles.find_one({"_id": user_data['role_id']})
            user = User(user_id=str(user_data["_id"]), username=user_data["name"], role=user_role["name"])
            login_user(user)
            if user_role.get('name') == "employee":
                return redirect(url_for('employee_bp.employee_dashboard'))
            elif user_role.get('name') == "manager":
                return redirect(url_for('manager_bp.manager_dashboard'))
            elif user_role.get('name') == "admin":
                return redirect(url_for('admin_bp.admin_dashboard'))
            else:
                flash('Invalid role!', 'danger')

            return redirect(url_for('admin_bp.admin_home'))
        else:
            flash('Login failed. Check your credentials.', 'danger')
    return render_template('login.html', form=form)


@login_bp.route('/logout')   # Focus here
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    logout_user()
    return redirect(url_for('login_bp.login'))
