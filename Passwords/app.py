# для удачного запуска проекта необходимо загрузить все модули, указанные в файле requirements.txt, а также выбрать нужный интерпретатор (желательно запускать в vsc)
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, has_special_chars, has_digit, encrypt, decrypt
import string
import secrets


app = Flask(__name__)


app.config["TEMPLATES_AUTO_RELOAD"] = True


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# подключение к бд
db = SQL("sqlite:///passwordmanage.db")

# генерация паролей
def generate_password(length, use_uppercase, use_lowercase, use_special_chars, use_numbers, exclude_chars):
    characters = ''
    
    if use_uppercase:
        characters += string.ascii_uppercase
    
    if use_lowercase:
        characters += string.ascii_lowercase
    
    if use_special_chars:
        characters += string.punctuation
    
    if use_numbers:
        characters += string.digits
    if exclude_chars:
        characters = characters.translate(str.maketrans('', '', exclude_chars))
    
    if not characters:
        return "Error: You must select at least one character type."
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

@app.route('/generate_password', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        length = int(request.form['length'])
        use_uppercase = 'uppercase' in request.form
        use_lowercase = 'lowercase' in request.form
        use_special_chars = 'special_chars' in request.form
        use_numbers = 'numbers' in request.form
        exclude_chars = request.form['exclude_chars']
        
        password = generate_password(length, use_uppercase, use_lowercase, use_special_chars, use_numbers, exclude_chars)
        return render_template('generate_password.html', password=password, default_length=length, default_exclude_chars=exclude_chars)
    
    return render_template('generate_password.html')

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


SECURITY_QUESTIONS = [
    "Ваше любимое время года?? ",
    "Ваш любимый питомец?",
    "Ваш любимый персонаж?",
    "Ваш любимый цвет?",
    "Ваше любимое блюдо?"
]


# Ключ #
SHIFT = 2


@app.route("/")
@login_required
def index():
    # показать обзор данных пользователя #
    passwords_data = db.execute("SELECT * FROM passwords WHERE username = ?", session["user_id"])
    cards_data = db.execute("SELECT * FROM cards WHERE username = ?", session["user_id"])
    notes_data = db.execute("SELECT * FROM notes WHERE username = ?", session["user_id"])
    return render_template("index.html", user=session["first_name"], passwords_data=len(passwords_data), cards_data=len(cards_data), notes_data=len(notes_data))


@app.route("/profile")
@login_required
def profile():
    # профиль пользователя #
    users_data = db.execute("SELECT * FROM users WHERE username = ?", session["user_id"])
    return render_template("profile.html", user=session["first_name"], users_data=users_data)


@app.route("/account")
@login_required
def account():

    return render_template("account.html", user=session["first_name"])


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    # Измененение пароля пользователя 
    if request.method == "POST":
        users_data = db.execute("SELECT * FROM users WHERE username = ?", session["user_id"])
        if request.form.get("new_password") != request.form.get("confirmation"):
            return apology("Пароли не совпадают")
        if check_password_hash(users_data[0]["password"], request.form.get("old_password")):
            db.execute("UPDATE users SET password = ? WHERE username = ?", generate_password_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8),
                       session["user_id"])
            flash('Пароль изменен!')
            return redirect("/account")
    return render_template("changepassword.html", user=session["first_name"])


@app.route("/deleteaccount", methods=["GET", "POST"])
@login_required
def deleteaccount():
    # удаление аккаунта
    if request.method == "POST":
        db.execute("DELETE FROM users WHERE username = ?", session["user_id"])
        db.execute("DELETE FROM passwords WHERE username = ?", session["user_id"])
        db.execute("DELETE FROM notes WHERE username = ?", session["user_id"])
        db.execute("DELETE FROM cards WHERE username = ?", session["user_id"])
        session.clear()
        return render_template("deleteaccount.html")
    return render_template("deleteaccount.html")


@app.route("/addpassword", methods=["GET", "POST"])
@login_required
def addpassword():
    # Добавление пароля
    if request.method == "POST":
        encrypted_password = encrypt(request.form.get("platform_password"), SHIFT)
        db.execute("INSERT INTO passwords (username, platform, platform_username, platform_password, password_comment) VALUES(?, ?, ?, ?, ?)",
                   session["user_id"], request.form.get("platform"), request.form.get("platform_username"), encrypted_password, request.form.get("password_comment"))
        flash('Пароль сохранен!')
        
    return render_template("addpassword.html", user=session["first_name"])


@app.route("/viewpasswords", methods=["GET", "POST"])
@login_required
def viewpasswords():
    # показ сохраненных паролей
    passwords_data = db.execute("SELECT * FROM passwords WHERE username = ?", session["user_id"])
    passwords = []
    for row in passwords_data:
        passwords.append(decrypt(row["platform_password"], SHIFT))

    return render_template("viewpasswords.html", passwords_data=passwords_data, passwords=passwords, length=len(passwords))


@app.route("/weakpasswords", methods=["GET", "POST"])
@login_required
def weakpasswords():
    # Показ слабых паролей из сохраненных паролей пользователя
    passwords = db.execute("SELECT platform, platform_username, platform_password FROM passwords WHERE username = ?", session["user_id"])
    weakpasswords = []
    userdata = []
    for i in passwords:
        temp = decrypt(i["platform_password"], SHIFT)
        if not has_special_chars(temp) or not has_digit(temp):
            userdata.append(i)
            weakpasswords.append(temp)
    return render_template("weakpasswords.html", weakpasswords=weakpasswords, userdata=userdata, length=len(weakpasswords))




@app.route("/deletepassword", methods=["GET", "POST"])
@login_required
def deletepassword():
    # Удаление пароля
    if request.method == "POST":
        db.execute("DELETE FROM passwords WHERE id = ?", request.form.get("id"))
        flash('Пароль удален!')
        return redirect("/viewpasswords")


@app.route("/updatepassword", methods=["GET", "POST"])
@login_required
def updatepassword():
    # Изменение пароля
    if request.method == "POST":
        db.execute("UPDATE passwords SET platform = ?, platform_username = ?, platform_password = ?, password_comment = ? WHERE id = ?",
                   request.form.get("new_platform"), request.form.get("new_platform_username"), encrypt(request.form.get("new_platform_password"), SHIFT),
                   request.form.get("new_password_comment"), request.form.get("id"))
        flash('Данные пароля обновлены!!')
        return redirect("/viewpasswords")

    return render_template("updatepassword.html", id=request.args.get("id"), platform_password=request.args.get("platform_password"),
                           platform_username=request.args.get("platform_username"), platform=request.args.get("platform"),
                           password_comment=request.args.get("password_comment"))



@app.route("/myaccount")
@login_required
def myaccount():
    """Shows account details of user"""
    # извлечение данных из нужных таблиц
    return render_template("myaccount.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # забыть все id
    session.clear()

    
    if request.method == "POST":

    
        if not request.form.get("username"):
            return apology("нужно ввести логин..", 403)

        elif not request.form.get("password"):
            return apology("нужно ввести пароль...", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # проверка подлинности логина и пароля
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("неправильный логин/пароль", 403)

        session["user_id"] = rows[0]["username"]
        session["first_name"] = rows[0]["first_name"]

        return redirect("/")

   
    else:
        return render_template("login.html")

# выход из уч.записи
@app.route("/logout")
def logout():
    """Log user out"""

    session.clear()

    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
#    регистрация пользователей
    if request.method == "POST":

        # проверка заполнености формы
        if not request.form.get("first_name") or not request.form.get("last_name") or not request.form.get("age") or not request.form.get("email") or not request.form.get("mobile_number"):
            return apology("Вы не закончили вводить данные!")

        # ввдена ли корректная почта
        email = request.form.get("email")
        if email.find("@") == -1 or email.startswith(".") or email.endswith(".") or len(email) < 4:
            return apology("Неправильная почта!")

        if not request.form.get("username"):
            return apology("Введите логин")
        
        elif not request.form.get("password"):
            return apology("Вы должны ввести паролей")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Пароли не совпадают!")

        # Введен неправильный секретный вопрос
        elif request.form.get("security_question") not in SECURITY_QUESTIONS:
            return apology("Неправильный секретный вопрос!")

        # Не введен секретный ответ
        if not request.form.get("security_answer"):
            return apology("Вы должны написать секретное слово")

        # Проверка на сущестующий логин
        username = request.form.get("username")
        existingUsername = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existingUsername:
            return apology("Такой логин уже существует!")

        # Проверка пароля на безопасность
        pass_word = request.form.get("password")
        if not has_special_chars(pass_word) or not has_digit(pass_word) or len(pass_word) < 7:
            return apology("Пароль не подходит требованиям безопасности!")

        # Отправление деталей на сервер
        password_hash = generate_password_hash(pass_word, method='pbkdf2:sha256', salt_length=8)
        security_question_hash = generate_password_hash(request.form.get("security_question"), method='pbkdf2:sha256', salt_length=8)
        security_answer_hash = generate_password_hash(request.form.get("security_answer"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, password, security_question, security_answer, first_name, last_name, age, email, mobile_number) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   username, password_hash, security_question_hash, security_answer_hash, request.form.get("first_name"), request.form.get("last_name"), request.form.get("age"),
                   request.form.get("email"), request.form.get("mobile_number"))
        flash('Успешная регистрация!')
        return render_template("login.html")
    return render_template("register.html", SECURITY_QUESTIONS=SECURITY_QUESTIONS)


@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    """Verify the user details to reset the password"""
    # Пользователь достиг маршрута через POST  при отправки формы
    if request.method == "POST":
        # Проверка на заполненность формы
        if not request.form.get("username") or not request.form.get("security_question") or request.form.get("security_answer") == "Select A Security Question":
            return apology("Незаполненные данные")

        # Проверка на наличие аккаунта
        username = request.form.get("username")
        userdata = db.execute("SELECT username, security_question, security_answer FROM users WHERE username = ?", username)
        if not userdata:
            return apology("Вы не зарегистрированы")
        elif check_password_hash(userdata[0]["security_question"], request.form.get("security_question")):
            if check_password_hash(userdata[0]["security_answer"], request.form.get("security_answer")):
                return render_template("passwordreset.html", username=username)
        return apology("Неправильный секретный вопрос")
    return render_template("forgotpassword.html", SECURITY_QUESTIONS=SECURITY_QUESTIONS)


@app.route("/resetpassword", methods=["GET", "POST"])
def resetpassword():
    """Reset the password"""

    # Проверка того, что пароль и подтверждение совпадают
    if request.form.get("password") != request.form.get("confirmation"):
        return apology("Пароли не совпадают")

    pass_hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
    db.execute("UPDATE users SET password = ? WHERE username = ?", pass_hash, request.form.get("username"))
    flash('Успешный сброс пароля!')
    return render_template("login.html")


if __name__ == '__main__':
    app.run(debug=True)