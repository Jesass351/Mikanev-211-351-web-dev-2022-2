from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL
from config import ERRORS_USERS, PERMITTED_CHARS_LOGIN, PERMITTED_CHARS_PASSWORD

import mysql.connector

app = Flask(__name__)
application = app

PERMITTED_PARAMS = ["login", "password", "last_name", "first_name", "middle_name", "role_id"]

app.config.from_pyfile('config.py')
db = MySQL(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо пройти процедуру аутентификации.'
login_manager.login_message_category = 'warning'

class User(UserMixin):
    def __init__(self, id, login):
        self.id = id
        self.login = login
        

@app.route('/')
def index():
    return render_template('index.html')

def authentificate_user(login, password):
    query = "SELECT * FROM users WHERE login = %s AND password_hash	= SHA2(%s, 256);"
    with db.connection.cursor(named_tuple = True) as cursor:
        cursor.execute(query, (login, password))
        print(cursor.statement)
        db_user = cursor.fetchone()
    if db_user is not None:
        user = User(db_user.id, db_user.login)
        return user
    return None

@login_manager.user_loader
def load_user(user_id):
    query = "SELECT * FROM users WHERE id = %s;"
    cursor = db.connection.cursor(named_tuple = True)
    cursor.execute(query, (user_id,))
    db_user = cursor.fetchone()
    cursor.close()
    if db_user is not None:
        user = User(user_id, db_user.login)
        return user
    return None

@app.route('/login', methods = ['POST', 'GET'])
def login():
    if request.method == "POST":
        user_login = request.form["loginInput"]
        user_password = request.form["passwordInput"]
        remember_me = request.form.get('remember_me') == 'on'

        auth_user = authentificate_user(user_login, user_password)
        if auth_user:
            login_user(auth_user, remember=remember_me)
            flash("Вы успешно авторизованы", "success")
            next_ = request.args.get('next')
            return redirect(next_ or url_for("index"))
            
        flash("Введены неверные логин и/или пароль", "danger") 

    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route('/users')
def users():
    query = "SELECT users.*, roles.name as role_name FROM users LEFT JOIN roles on users.role_id=roles.id;"
    with db.connection.cursor(named_tuple = True) as cursor:
        cursor.execute(query)
        print(cursor.statement)
        db_users = cursor.fetchall()
    return render_template('users/index.html', users = db_users)

def load_roles():
    query = "SELECT * FROM roles;"
    with db.connection.cursor(named_tuple = True) as cursor:
        cursor.execute(query)
        db_roles = cursor.fetchall()
    return db_roles

@app.route('/users/new')
@login_required
def new_user():
    return render_template('users/new.html', roles = load_roles(), user={}, errors={})

def insert_to_db(params):
    query = """
        INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id) 
        VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(role_id)s);
    """
    try:
        with db.connection.cursor(named_tuple = True) as cursor:
            cursor.execute(query, params)
            db.connection.commit()
    except mysql.connector.errors.DatabaseError:
        db.connection.rollback()
        return False

    return True

def validation_edit(params):
    errors_res = {
        "login": None,
        "last_name": None,
        "first_name": None,
        "is_validate": 1,
    }
    
    #Проверка логина
    login = params.get("login")
    if login is None:
        errors_res["login"] = ERRORS_USERS["empty_login"]
        errors_res["is_validate"] = 0
    elif len(login) < 5:
        errors_res["login"] = ERRORS_USERS["login_too_small"]
        errors_res["is_validate"] = 0
    else:
        for char in login:
             if (char.lower() not in PERMITTED_CHARS_LOGIN ):
                 errors_res["login"] = ERRORS_USERS["login_incorrect_chars"]
                 errors_res["is_validate"] = 0
                 break
             
    #Проверка имени
    if params.get("first_name") is None:
        errors_res["first_name"] = ERRORS_USERS["empty_first_name"]
        errors_res["is_validate"] = 0

    #Проверка фамилии
    if params.get("last_name") is None:
        errors_res["last_name"] = ERRORS_USERS["empty_last_name"]
        errors_res["is_validate"] = 0

    return errors_res

def check_login(login):
    if login is None:
        return ERRORS_USERS["empty_login"]
    elif len(login) < 5:
        return ERRORS_USERS["login_too_small"]
    else:
        for char in login:
            if char.lower() not in PERMITTED_CHARS_LOGIN:
                return ERRORS_USERS["login_incorrect_chars"]
    return None

def check_last_name(last_name):
    if last_name is None:
        return ERRORS_USERS["empty_last_name"]
    return None

def check_first_name(first_name):
    if first_name is None:
        return ERRORS_USERS["empty_first_name"]
    return None

def check_password(password):
    counter_upper = 0
    counter_lower = 0
    counter_digits = 0
    
    if password is None:
        return ERRORS_USERS["empty_passwd"]
    elif len(password) < 8:
        return ERRORS_USERS["password_too_small"]
    elif len(password) > 128:
        return ERRORS_USERS["password_too_big"]
    elif password.find(" ") > -1:
        return ERRORS_USERS["password_has_spaces"]
    else:
        for char in password:
            if char.lower() not in PERMITTED_CHARS_PASSWORD:
                return ERRORS_USERS["password_incorrect_chars"]
            elif char.isalpha():
                if char.isupper():
                    counter_upper += 1
                else:
                    counter_lower += 1
            elif char.isdigit():
                counter_digits += 1
        if counter_lower < 1:
            return ERRORS_USERS["password_no_lower"]
        elif counter_upper < 1:
            return ERRORS_USERS["password_no_upper"]
        elif counter_digits < 1:
            return ERRORS_USERS["password_no_digit"]
    return None

def validate_create(params):
    errors_res = {
        "login": None,
        "password": None,
        "last_name": None,
        "first_name": None,
        "is_validate": 1,
    }
    login = params.get("login")
    last_name = params.get("last_name")
    first_name = params.get("first_name")
    password = params.get("password")
    #Проверка логина
    login_check_res = check_login(login)
    if (login_check_res is not None):
        errors_res["login"] = login_check_res
        errors_res["is_validate"] = 0
             
    #Проверка фамилии
    last_name_res = check_last_name(last_name)
    if (last_name_res is not None):
        errors_res["last_name"] = last_name_res
        errors_res["is_validate"] = 0

    #Проверка имени
    first_name_res = check_first_name(first_name)
    if (last_name_res is not None):
        errors_res["first_name"] = first_name_res
        errors_res["is_validate"] = 0

    #Проверка пароля
    check_password_res = check_password(password)
    if (check_password_res is not None):
        errors_res["password"] = check_password_res
        errors_res["is_validate"] = 0
    
    return errors_res
            
def params(names_list):
    result = {}
    for name in names_list:
        result[name] = request.form.get(name) or None
    return result

@app.route('/users/create', methods=['POST'])
@login_required
def create_user():
    cur_params = params(PERMITTED_PARAMS)
    errors_res = validate_create(cur_params)
    if errors_res["is_validate"] == 0:
        flash("Проверьте правильность введённых данных", "danger")
        return render_template("users/new.html", roles = load_roles(), user=cur_params, errors=errors_res)
    
    inserted = insert_to_db(cur_params)
    if inserted:
        flash("Пользователь успешно добавлен", "success")
        return redirect(url_for("users"))
    else:
        flash("При сохранении возникла ошибка", "danger")
        return render_template("users/new.html", roles = load_roles(), user=cur_params, errors=errors_res)

@app.route('/users/<int:user_id>/edit', methods=['GET'])
@login_required
def edit_user(user_id):
    edit_select = "SELECT * FROM users WHERE id = %s;"
    errors = {}
    with db.connection.cursor(named_tuple = True) as cursor:
        cursor.execute(edit_select, (user_id,))
        user = cursor.fetchone()
        if user is None:
            flash("Пользователь не найден", "warning")
            return redirect(url_for("users"))
        
    return render_template("users/edit.html", user=user, roles=load_roles(), errors=errors)

@app.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
def update_user(user_id):
    cur_params = params(PERMITTED_PARAMS)
    errors = validation_edit(cur_params)
    cur_params["id"] = user_id
    update_query = """
    UPDATE users SET login = %(login)s, last_name = %(last_name)s, 
    first_name = %(first_name)s, middle_name = %(middle_name)s,
    role_id = %(role_id)s WHERE id = %(id)s;
    """
    if errors["is_validate"] == 0:
        flash("Проверьте правильность введённых данных", "danger")
        return render_template('users/edit.html', user=cur_params, roles=load_roles(), errors=errors)
    try:
        with db.connection.cursor(named_tuple = True) as cursor:
            cursor.execute(update_query, cur_params)
            db.connection.commit()
            flash("Пользователь успешно обновлен", "success")
    except mysql.connector.errors.DatabaseError:
        flash("При изменении возникла ошибка", "danger")
        db.connection.rollback()
        return render_template('users/edit.html', user=cur_params, roles=load_roles(), errors=errors)
        
    return redirect(url_for("users"))
    
    
@app.route("/users/<int:user_id>")
def show_user(user_id):
    with db.connection.cursor(named_tuple = True) as cursor:
        query="SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        db_user = cursor.fetchone()
    if db_user is None:
        flash("Пользователь не найден", "danger")
        return redirect(url_for("users"))
    
    return render_template('users/show.html', user=db_user)

@app.route("/users/<int:user_id>/delete", methods=['POST'])
@login_required
def delete_user(user_id):
    delete_query="DELETE FROM users WHERE id = %s"
    try:
        with db.connection.cursor(named_tuple = True) as cursor:
            cursor.execute(delete_query, (user_id,))
            db.connection.commit()
            flash("Пользователь успешно удален", "success")
    except mysql.connector.errors.DatabaseError:
        flash("При удалении произошла ошибка", "danger")
        db.connection.rollback()
    return redirect(url_for("users"))

@app.route("/update_password", methods=['GET', 'POST'])
@login_required
def update_password():
    user_id = current_user.id
    errors_res = {
        "old": None,
        "password": None, 
        "repeate": None,
        "is_validate": 1,
    }
    old_password = None
    new_password = None
    if request.method == "POST":
        old_password = request.form.get("oldPassword")
        new_password = request.form.get("newPassword")
        repeate_password = request.form.get("repeateNewPassword")
        query = "SELECT * FROM users WHERE id = %s AND password_hash = SHA2(%s, 256);"
        with db.connection.cursor(named_tuple = True) as cursor:
            cursor.execute(query, (user_id, old_password))
            db_user = cursor.fetchone()
            if db_user is None:
                errors_res["old"] = ERRORS_USERS["incorrect_password"]
                errors_res["is_validate"] = 0
            validate_password = check_password(new_password)
            if validate_password is not None:
                errors_res["password"] = validate_password
                errors_res["is_validate"] = 0
            if new_password != repeate_password:
                errors_res["repeate"] = ERRORS_USERS["incorrect_same_password"]
                errors_res["is_validate"] = 0
        if errors_res.get("is_validate") == 0:
            flash("Проверьте введённые данные", "danger")
            return render_template('update_password.html', errors=errors_res, old=old_password, new=new_password)
    
        update_query = "UPDATE users SET password_hash = SHA2(%s, 256) WHERE id = %s;"
        try:
            with db.connection.cursor(named_tuple = True) as cursor:
                cursor.execute(update_query, (repeate_password, user_id))
                db.connection.commit()
                flash("Пароль успешно обновлен", "success")
                return redirect(url_for("index"))
        except mysql.connector.errors.DatabaseError:
            flash("При изменении возникла ошибка", "danger")
            db.connection.rollback()
            return render_template('update_password.html', errors=errors_res, old=old_password, new=new_password)
    return render_template('update_password.html', errors=errors_res, old=old_password, new=new_password)