from flask import Flask
from config import Config
from app.routes import register_blueprints

def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    register_blueprints(app)

    return app