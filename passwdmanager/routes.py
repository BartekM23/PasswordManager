import hashlib
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, login_required, current_user, logout_user
from passwdmanager.forms import RegisterForm, LoginForm, ChangePassword, FormAddPassword, FormSharePassword, FormResetPassword
from passwdmanager.PasswordFeatures import make_salt, PEPPER, NUM_OF_ITER, is_password_strong_entropy
from passwdmanager.AESCipher import encrypt, decrypt
from flask_mail import Message
from passwdmanager.models import User, Password, UserPassword
import time
from passwdmanager import app, db, login_manager, mail


# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def hello():
    return render_template('index.html', current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('hello'))

    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        password += PEPPER

        user = User.query.filter_by(email=email).first()
        salt = user.salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), NUM_OF_ITER)

        if not user:
            time.sleep(0.2)
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        elif not user.password_hash == hashed_password.hex():
            flash('Password incorrect, please try again.')
            time.sleep(0.2 + 0.1 * user.num_of_incorrect_login)
            user.num_of_incorrect_login += 1
            db.session.commit()
            return redirect(url_for('login'))

        else:
            time.sleep(0.2)
            user.num_of_incorrect_login = 0
            db.session.commit()
            login_user(user)
            return redirect(url_for('hello'))
    return render_template('login.html', form=login_form, current_user=current_user)


@app.route('/change_password', methods=["POST", "GET"])
@login_required
def change_password():
    change_password_form = ChangePassword()
    if change_password_form.validate_on_submit():

        old_password = change_password_form.old_password.data
        old_password += PEPPER

        user = User.query.filter_by(email=current_user.email).first()
        salt = user.salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', old_password.encode(), salt.encode(), NUM_OF_ITER)

        if not user.password_hash == hashed_password.hex():
            flash('Password incorrect, please try again.')
            return redirect(url_for('change_password'))
        elif not is_password_strong_entropy(change_password_form.new_password.data):
            flash('Password too weak, please use harder one.')
            return redirect(url_for('register'))

        else:
            salt = make_salt()
            new_password = change_password_form.new_password.data
            new_password += PEPPER
            new_hashed_password = hashlib.pbkdf2_hmac('sha256', new_password.encode(),
                                                      salt.encode(), NUM_OF_ITER)

            user.salt = salt
            db.session.commit()
            user.password_hash = new_hashed_password.hex()
            db.session.commit()
            return redirect(url_for('hello'))
    return render_template('change_password.html', form=change_password_form, current_user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    register_form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('hello'))
    if register_form.validate_on_submit():

        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        password = register_form.password.data

        if not is_password_strong_entropy(password):
            flash('Password too weak, please use harder one.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=register_form.username.data).first():
            flash('There is already user with this username.')
            return redirect(url_for('register'))

        password += PEPPER
        salt = make_salt()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), NUM_OF_ITER)

        new_user = User(email=register_form.email.data,
                        password_hash=hashed_password.hex(),
                        salt=salt,
                        username=register_form.username.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("hello"))
    return render_template('register.html', form=register_form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello'))


@app.route('/add_password', methods=["POST", "GET"])
@login_required
def add_password():
    form = FormAddPassword()
    if form.validate_on_submit():
        new_password = Password(password=encrypt(form.password.data),
                                domain_name=form.domain_name.data,
                                author=current_user.username)
        db.session.add(new_password)
        db.session.commit()
        user_passwd = UserPassword(user_id=current_user.id,
                                   password_id=new_password.id)
        db.session.add(user_passwd)
        db.session.commit()

        return redirect(url_for('hello'))
    return render_template('add_password_for_myself.html', current_user=current_user, form=form)


@app.route('/show_passwords')
@login_required
def show_passwords():
    user_passwd = UserPassword.query.filter_by(user_id=int(current_user.id)).all()
    passwords = []
    for item in user_passwd:
        passwords.append(Password.query.filter_by(id=item.password_id).first())
    for passwd in passwords:
        passwd.password = decrypt(passwd.password).decode('utf-8')

    return render_template('show_passwords.html', current_user=current_user, passwords=passwords)


@app.route('/share_password/<int:password_id>', methods=["POST", "GET"])
@login_required
def share_password(password_id):
    form = FormSharePassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('There is no user with such email. You did not shared password!')
            return redirect(url_for('hello'))
        elif UserPassword.query.filter_by(user_id=user.id, password_id=password_id).first():
            flash('This user already has access to this password.')
            return redirect(url_for('hello'))
        else:
            user_passwd = UserPassword(user_id=user.id,
                                       password_id=password_id)
            db.session.add(user_passwd)
            db.session.commit()
            return redirect(url_for('hello'))

    return render_template('share_password.html', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f"""To reset your password visit following link: {url_for('reset_token', token=token, _external=True)} 
    If you did not make this request, ignore this"""
    mail.send(msg)


@app.route('/reset_password', methods=["POST", "GET"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('hello'))
    form = FormSharePassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('There is no user with such email')
            return redirect(url_for('reset_request'))
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.')
        return redirect(url_for('login'))

    return render_template('reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=["POST", "GET"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('hello'))
    user = User.verify_reset_token(token)
    if not user:
        flash('That is invalid/expired token')
        return redirect(url_for('reset_request'))
    form = FormResetPassword()
    if form.validate_on_submit():

        password = form.new_password.data

        if not is_password_strong_entropy(password):
            flash('Password too weak, please use harder one.')
            return redirect(url_for('reset_token', token=token))

        password += PEPPER
        salt = make_salt()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), NUM_OF_ITER)
        user.salt = salt
        db.session.commit()
        user.password_hash = hashed_password.hex()
        db.session.commit()
        login_user(user)
        return redirect(url_for("hello"))
    return render_template('reset_token.html', form=form)


