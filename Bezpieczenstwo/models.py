from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from app import db, app
from flask_login import UserMixin
from sqlalchemy.orm import relationship


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(150))
    salt = db.Column(db.String(100))
    num_of_incorrect_login = db.Column(db.Integer, default=0)

    passwords = relationship('Password', secondary="users_passwords")

    def get_reset_token(self, expire_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expire_sec)
        return s.dumps({"user_id": self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class Password(db.Model):
    __tablename__ = "passwords"
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(150))
    password = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(120))

    users = relationship('User', secondary="users_passwords")


class UserPassword(db.Model):
    __tablename__ = "users_passwords"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    password_id = db.Column(db.Integer, db.ForeignKey('passwords.id'))
