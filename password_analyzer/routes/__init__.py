from app.routes.analysis import analysis_bp

def register_blueprints(app):
    app.register_blueprint(analysis_bp)