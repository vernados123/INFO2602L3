from flask import Flask, jsonify, request
from functools import wraps
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)

from models import Admin, Category, RegularUser, Todo, TodoCategory, db, User

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'MySecretKey'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

db.init_app(app)
app.app_context().push()
CORS(app)

jwt = JWTManager(app)

# customn decorator authorize routes for admin or regular user
def login_required(required_class):
  def wrapper(f):
      @wraps(f)
      @jwt_required()  # Ensure JWT authentication
      def decorated_function(*args, **kwargs):
        user = required_class.query.filter_by(username=get_jwt_identity()).first()  
        print(user.__class__, required_class, user.__class__ == required_class)
        if user.__class__ != required_class:  # Check class equality
            return jsonify(message='Invalid user role'), 403
        return f(*args, **kwargs)
      return decorated_function
  return wrapper

@app.route('/')
def index():
  return '<h1>mY Todo API</h1>'

# Task 3.1 Here

# Task 3.2 Here

# Task 3.3 Here

# Task 3.4 Here

# Task 4 Here

# ********** Todo Crud Operations ************


# Task 5.1 Here POST /todos

# Task 5.2 Here GET /todos

# Task 5.3 Here GET /todos/id

# Task 5.4 Here PUT /todos/id

# Task 5.5 Here DELETE /todos/id

@app.route('/todos/stats', methods=['GET'])
@login_required(RegularUser)
def get_stats_view():
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()
  return jsonify(num_todos=user.getNumTodos(),
                 num_done=user.getDoneTodos()), 200


if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)
