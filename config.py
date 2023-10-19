import os

from flask_pymongo import PyMongo

mongo = PyMongo()


class Config:
    MONGO_URI = "mongodb://localhost:27017/myDatabase"
    SECRET_KEY = os.environ.get('SECRET_KEY') or '123'
