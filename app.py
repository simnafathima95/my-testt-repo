from bson import ObjectId

from flask import Flask
from flask_login import LoginManager

from config import mongo, Config
from users import routes
from users.user import User


app = Flask(__name__)

app.config.from_object(Config)
mongo.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    print("eeeeeeeee")
    user_id = ObjectId(user_id)
    user_data = mongo.db.users.find_one({"_id": user_id})
    user = User(user_id, username=user_data.get("name"), role=mongo.db.roles.find_one({'_id': user_data['role_id']})["name"])
    return user


app.register_blueprint(routes.admin_bp)
app.register_blueprint(routes.permissions_bp)
app.register_blueprint(routes.roles_bp)
app.register_blueprint(routes.login_bp)
app.register_blueprint(routes.employee_bp)
app.register_blueprint(routes.manager_bp)
app.register_blueprint(routes.export_bp)
