import os
import uuid
import jwt
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+os.path.join(BASE_DIR, 'site.db')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    todos = db.relationship('Todo', backref='author', lazy=True)

    def as_dict(self):
        user_data = {}
        user_data['public_id'] = self.public_id
        user_data['name'] = self.name
        user_data['password'] = self.password
        user_data['admin'] = self.admin
        return user_data

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    completed = db.Column(db.Boolean, nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def as_dict(self):
        todo_data = {}
        todo_data['id'] = self.id
        todo_data['text'] = self.text
        todo_data['completed'] = self.completed
        return todo_data

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"Message" : "Token is missing, try logging in via the login route"})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"Message" : "The token is invalid or expired, try logging in again"})
        return f(current_user, *args, **kwargs)
    return decorated

def is_admin(current_user):
    if current_user.admin:
        return True
        

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if is_admin(current_user):
        users = User.query.all()
        output = []
        for user in users:
            output.append(user.as_dict())
        return jsonify({"users" : output})
    else:
        return jsonify({"Message" : "You don't have the right permissions to do that!"}), 403

@app.route('/user/<string:public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if is_admin(current_user):
        user = User.query.filter_by(public_id=public_id).first_or_404()
        output = user.as_dict()
        return jsonify({"user" : output})
    else:
        return jsonify({"Message" : "You don't have the right permissions to do that!"}), 403

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if is_admin(current_user):
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
        db.session.add(user)
        db.session.commit()
        return jsonify({"Message" : "New user created succesfully!"})
    else:
        return jsonify({"Message" : "You don't have the right permissions to do that!"}), 403

@app.route('/user/<string:public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if is_admin(current_user):
        user = User.query.filter_by(public_id=public_id).first_or_404()
        db.session.delete(user)
        db.session.commit()
        return jsonify({"Message" : "User removed succesfully!"})
    else:
        return jsonify({"Message" : "You don't have the right permissions to do that!"}), 403

@app.route('/user/<string:public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if is_admin(current_user):
        user = User.query.filter_by(public_id=public_id).first_or_404()
        user.admin = True
        db.session.commit()
        return jsonify({"Message" : "The requested user has been promoted to admin role"})
    else:
        return jsonify({"Message" : "You don't have the right permissions to do that!"}), 403

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify, please check your username and password", 401, {"WWW-Authenticate" : "Basic realm='Login required!'"})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response("Could not verify, please check your username and password", 401, {"WWW-Authenticate" : "Basic realm='Login required!'"})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id" : user.public_id, "exp" : datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"token" : token})
    return make_response("Could not verify, please check your username and password", 401, {"WWW-Authenticate" : "Basic realm='Login required!'"})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todo(current_user):
    todos = Todo.query.filter_by(author=current_user)
    output = []
    for task in todos:
        output.append(task.as_dict())
    return jsonify({"output" : output})

@app.route('/todo/<int:todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, author=current_user).first_or_404()
    output = todo.as_dict()
    return jsonify({"task" : output})

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    task = Todo(text=data['text'], completed=False, user=current_user.id)
    db.session.add(task)
    db.session.commit()
    return jsonify({"Message" : "New task created succesfully!"})

@app.route('/todo/<int:todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, author=current_user).first_or_404()
    todo.completed = True
    db.session.commit()
    return jsonify({"Message" : "The task has been marked as completed"})

@app.route('/todo/<int:todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, author=current_user).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"Message" : "The task has been deleted!"})

if __name__ == '__main__':
    app.run(debug = True)