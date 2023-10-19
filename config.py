import os
from bson import ObjectId

from flask_pymongo import PyMongo

from users.user import User


mongo = PyMongo()


class Config:
    MONGO_URI = "mongodb://localhost:27017/emerson_db"
    SECRET_KEY = os.environ.get('SECRET_KEY') or '123'


def load_user(user_id):
    user_id = ObjectId(user_id)
    if user_id:
        user_data = mongo.db.users.find_one({"_id": user_id})
        if user_data:
            user = User(
                user_id, username=user_data.get("name"),
                role=mongo.db.roles.find_one({'_id': user_data['role_id']})["name"]
            )
            return user
