from bson import ObjectId
from functools import wraps

from flask import redirect, url_for, flash

from flask_login import current_user

from config import mongo


def get_manager_role():
    manager_role = mongo.db.roles.find_one({'name': 'manager'})
    return manager_role


def get_managers():
    manager_role = get_manager_role()
    if manager_role:
        manager_role_id = manager_role['_id']
        managers = mongo.db.users.find({'role_id': manager_role_id})
        return managers
    return []


def get_employee_role():
    employee_role = mongo.db.roles.find_one({'name': 'employee'})
    return employee_role


def get_employees():
    employee_role = get_employee_role()
    if employee_role:
        employee_role_id = employee_role['_id']
        employees = list(mongo.db.users.find({'role_id': employee_role_id}))
        for employee in employees:
            manager_id = employee.get('manager')
            if manager_id:
                manager = mongo.db.users.find_one({'_id': manager_id})
                if manager:
                    employee['manager_name'] = manager['name']
        return employees
    return []


def get_permissions():
    return mongo.db.permissions.find()


def get_roles():
    roles = list(mongo.db.roles.find({'name': {'$ne': 'admin'}}))
    for role in roles:
        permissions_ids = role.get('permissions_ids', [])
        permission_names = []
        for each in permissions_ids:
            permission = mongo.db.permissions.find_one({'_id': each})
            if permission:
                permission_names.append(permission['name'])
        role['permission_names'] = ", ".join(permission_names)
    return roles


def is_email_exists(email):
    existing_emails = [employee['email'] for employee in mongo.db.users.find({}, {"email": 1})]
    if email in existing_emails:
        return True
    return False


def is_phonenumber_exists(email):
    existing_phone = [employee['phone'] for employee in mongo.db.users.find({}, {"phone": 1})]
    if email in existing_phone:
        return True
    return False


def role_required(required_roles):
    def decorated_function(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_user.is_authenticated and current_user.role in required_roles:
                return f(*args, **kwargs)
            else:
                flash("You don't have permission to access this page.", 'danger')
                return redirect(url_for('login_bp.login'))  # Redirect to your login route

        return wrapper
    return decorated_function


def modify_employee_data(data):
    for item in data:
        print(item)
        item.pop('password', '')
        item.pop('role_id', '')
        item.pop('manager', '')
        for each in item:
            if isinstance(item[each], ObjectId):
                item[each] = str(item[each])
    return data


def get_role_data(filter_role):
    role = mongo.db.roles.find_one({'name': filter_role})
    permissions_ids = role.get('permissions_ids', [])
    permission_names = []
    for each in permissions_ids:
        permission = mongo.db.permissions.find_one({'_id': each})
        if permission:
            permission_names.append(permission['name'])
            role['permission_names'] = permission_names
    return {"name": role.get("name"), "permission_names":  role.get('permission_names')}
