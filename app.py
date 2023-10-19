from flask import Flask
from flask_login import LoginManager

from config import mongo, Config, load_user
from users import routes


app = Flask(__name__)

app.config.from_object(Config)
mongo.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.user_loader(load_user)

app.register_blueprint(routes.admin_bp)
app.register_blueprint(routes.permissions_bp)
app.register_blueprint(routes.roles_bp)
app.register_blueprint(routes.login_bp)
app.register_blueprint(routes.employee_bp)
app.register_blueprint(routes.manager_bp)
app.register_blueprint(routes.export_bp)
