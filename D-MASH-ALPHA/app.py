import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory , flash
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, or_, and_, not_, LargeBinary
from sqlalchemy.sql import exists, text
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app)


UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Создаем базу данных SQLite и таблицы для сообщений и пользователей
engine = create_engine('sqlite:///messenger.db', echo=True)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, nullable=False)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

class Group(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True, nullable=False)
    groupname = Column(String, unique=True, nullable=False)
    creator = Column(String, nullable=False)

class UserGroup(Base):
    __tablename__ = 'user_group'
    username = Column(String, primary_key=True, nullable=False)
    groupname = Column(String, primary_key=True, nullable=False)

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, nullable=False)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)  # 'general' for general chat, username for private chat
    content = Column(String, nullable=True)
    timestamp = Column(DateTime, default= datetime.now, nullable=False)
    is_file = Column(Integer, default=0, nullable=True) # 0 - text message, 1 - file

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
db_session = Session()



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = str(int(datetime.now().timestamp())) + '_' + file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'url': url_for('uploaded_file', filename=filename)})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/create_group', methods=["GET", "POST"])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = db_session.query(User).all()
    current_user = session['username']
    if request.method == "POST":
        groupname = request.form["group_name"].strip()

        # Проверка на пустое имя группы
        if not groupname:
            flash('Имя группы не может быть пустым. Пожалуйста, введите имя группы.')
            return redirect(url_for('create_group'))

        # Проверка, существует ли группа с таким именем
        existing_group = db_session.query(Group).filter_by(groupname=groupname).first()
        if existing_group:
            flash('Группа с таким именем уже существует. Пожалуйста, выберите другое имя.')
            return redirect(url_for('create_group'))

        # Создание новой группы
        group = Group(groupname=groupname, creator=current_user)
        db_session.add(group)
        
        # Добавление пользователей в группу
        selected_users = json.loads(request.form["users"])
        for user in selected_users:
            user_group = UserGroup(groupname=groupname, username=user)
            db_session.add(user_group)


        try:
            db_session.commit()
            isGroup = db_session.query(
                db_session.query(UserGroup).filter(
                and_(
                    UserGroup.username == current_user,
                    UserGroup.groupname == groupname
                        )
                    ).exists()
                ).scalar()
            if not isGroup:
                user_group = UserGroup(groupname=groupname, username=current_user)
                db_session.add(user_group)
        except IntegrityError:
            db_session.rollback()
            flash('Произошла ошибка при создании группы. Пожалуйста, попробуйте снова.')
            return redirect(url_for('create_group'))

        return redirect(url_for('index'))
    
    return render_template("create_group.html", users=users, current_user=current_user)




@app.route("/")
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = db_session.query(User).all()
    current_user = session['username']
    groups = db_session.query(UserGroup).filter(UserGroup.username == current_user).all()
    return render_template("index.html", groups=groups, users=users, current_user=current_user)

@app.route("/chat/<recipient>")
def chat(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))
    users = db_session.query(User).all()
    current_user = session['username']
    groups = db_session.query(UserGroup).filter(UserGroup.username == current_user).all()
    isGroup = db_session.query(
    db_session.query(UserGroup).filter(
        and_(
            UserGroup.username == session['username'],
            UserGroup.groupname == recipient
                )
            ).exists()
        ).scalar()
    users_in_group=[]
    is_Creator= False
    if isGroup:
        users_in_group = db_session.query(UserGroup.username).filter_by(groupname = recipient).all()
        is_Creator = db_session.query(
            db_session.query(Group).filter(
                and_(
                    Group.creator == session['username'],
                    Group.groupname == recipient
                    )
                ).exists()
            ).scalar()
        print(users_in_group)

    return render_template("chat.html", users_in_group = users_in_group, is_Creator = is_Creator , isGroup=isGroup, groups=groups, current_user = session['username'], recipient = recipient , users=users)

@socketio.on('join')
def on_join(data):
    username = session['username']
    room = data['room']
    join_room(room)
    emit('status', {'msg': username + ' has entered the room.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    username = session['username']
    room = data['room']
    leave_room(room)
    emit('status', {'msg': username + ' has left the room.'}, room=room)

@socketio.on('send_message')
def handle_message(data):
    sender = session['username']
    recipient = data['recipient']
    content = data['content']
    is_file = data.get('is_file', 0)

    message = Message(sender=sender, recipient=recipient, content=content, is_file=is_file)
    db_session.add(message)
    db_session.commit()
    isGroup = db_session.query(
    db_session.query(UserGroup).filter(
        and_(
            UserGroup.username == session['username'],
            UserGroup.groupname == recipient
                )
            ).exists()  
        ).scalar()
    
    if recipient == 'general':
        for user in [u.username for u in db_session.query(User).all()]:
            emit('message', {'sender': sender, 'recipient': recipient ,'content': content, 'timestamp': message.timestamp.strftime('%H:%M'), 'is_file': is_file}, room=user)
    elif isGroup:
        users_in_group = db_session.query(UserGroup).filter_by(groupname = recipient).all()
        for user in users_in_group:
            emit('message', {'sender': sender, 'recipient': recipient ,'content': content, 'timestamp': message.timestamp.strftime('%H:%M'), 'is_file': is_file}, room=user.username)
    else:
        if sender != recipient:
            emit('message', {'sender': sender, 'recipient': recipient , 'content': content, 'timestamp': message.timestamp.strftime('%H:%M'), 'is_file': is_file}, room=recipient)
        emit('message', {'sender': sender, 'recipient': recipient , 'content': content, 'timestamp': message.timestamp.strftime('%H:%M'), 'is_file': is_file}, room=sender)



@app.route("/get_messages/<recipient>")
def get_messages(recipient):
    if 'username' not in session:
        return jsonify([])

    isGroup = db_session.query(
    db_session.query(UserGroup).filter(
        and_(
            UserGroup.username == session['username'],
            UserGroup.groupname == recipient
                )
            ).exists()
        ).scalar()

    if recipient == 'general':
        messages = db_session.query(Message).filter_by(recipient='general').all()
    elif isGroup:
        messages = db_session.query(Message).filter_by(recipient=recipient).all()
    else:
        messages = db_session.query(Message).filter(
            or_(
                (Message.sender == session['username']) & (Message.recipient == recipient),
                (Message.sender == recipient) & (Message.recipient == session['username'])
            )
        ).all()
    messages_list = [{
        'sender': message.sender,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%H:%M'),
        'is_file': message.is_file
    } for message in messages]

    return jsonify(messages_list)

    

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            password_confirm = request.form["password_confirm"]
            user_q = db_session.query(User).filter_by(username=username).first()
            if user_q == []:
                flash('Пользователь с таким именем уже существует')
                return redirect(url_for('register'))
            if password != password_confirm:
                flash('Пароли не совпадают')
                return redirect(url_for('register'))
            password_hash = generate_password_hash(password)
            user = User(username=username, password_hash=password_hash)
            db_session.add(user)
            db_session.commit()
            session['username'] = username
            return redirect(url_for('index'))
        except Exception as e:
            flash(e)
            return redirect(url_for('register'))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = db_session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль')
            return redirect(url_for('login'))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/send_message/<recipient>", methods=["POST"])
def send_message(recipient):
    if 'username' not in session:
        return redirect(url_for('login'))
    sender = session['username']
    content = request.form["content"]
    message = Message(sender=sender, recipient=recipient, content=content)
    db_session.add(message)
    db_session.commit()
    return redirect(url_for("chat", recipient=recipient))

# Проверка сессии в начале каждой функции-обработчика
@app.route('/admin')
def admin_index():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_index.html')

@app.route('/admin/tables')
def admin_tables():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    tables = db_session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
    table_names = [row[0] for row in tables]
    return render_template('admin_tables.html', tables=table_names)

@app.route('/admin/table/<table_name>')
def admin_table(table_name):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    rows = db_session.execute(text(f"SELECT * FROM {table_name}")).fetchall()
    columns = [column[0] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
        # Получаем названия столбцов (имена колонок)
    column_names = [column[1] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    return render_template('admin_table.html', table_name=table_name, rows=rows, columns=columns, column_names=column_names)


@app.route('/admin/table/<table_name>/edit/<record_id>')
def admin_edit_record(table_name, record_id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    record = db_session.execute(text(f"SELECT * FROM {table_name} WHERE id = {record_id}")).fetchone()
    columns = [column[0] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    len_columns=len(columns)
    column_names = [column[1] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    return render_template('admin_edit_record.html', table_name=table_name,len_columns=len_columns, record=record, columns=columns, column_names=column_names)

@app.route('/admin/table/<table_name>/edit/<record_id>', methods=['POST'])
def admin_update_record(table_name, record_id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    data = request.form
    columns = [column[0] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    
    # Создаем список кортежей (имя_столбца, значение)
    values = [(column, data.get(column)) for column in columns] 

    update_query = f"UPDATE {table_name} SET "
    update_query += ", ".join([f"{column} = ?" for column in columns])
    update_query += f" WHERE id = {record_id}"
    db_session.execute(text(update_query), values)  # Передаем список кортежей
    return redirect(url_for('admin_table', table_name=table_name))

@app.route('/admin/table/<table_name>/delete/<record_id>')
def admin_delete_record(table_name, record_id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    db_session.execute(text(f"DELETE FROM {table_name} WHERE id = {record_id}"))
    return redirect(url_for('admin_table', table_name=table_name))

@app.route('/admin/table/<table_name>/add', methods=['GET', 'POST'])
def admin_add_record(table_name):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    columns = [column[0] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    len_columns=len(columns)
    column_names = [column[1] for column in db_session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()]
    if request.method == 'POST':
        data = request.form
        values = [data.get(column) for column in columns]
        insert_query = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({', '.join(['?'] * len(columns))})"
        db_session.execute(text(insert_query), values)

        return redirect(url_for('admin_table', table_name=table_name))
    return render_template('admin_add_record.html', table_name=table_name, columns=columns,len_columns=len_columns,column_names=column_names)



@app.route('/admin/sql', methods=['GET', 'POST'])
def admin_sql():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        sql_query = request.form['sql_query']
        try:
            results = db_session.execute(text(sql_query)).fetchall()
            # Correctly extract column names from the results
            columns = [column[0] for column in results[0].keys()] 
            return render_template('admin_sql_results.html', results=results, columns=columns)
        except Exception as e:
            return render_template('admin_sql.html', error=str(e))
    return render_template('admin_sql.html')

@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    user = db_session.query(User).get(user_id)
    if user:
        db_session.delete(user)
        db_session.commit()
    return redirect(url_for('admin'))

@app.route("/delete_message/<int:message_id>")
def delete_message(message_id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    message = db_session.query(Message).get(message_id)
    if message:
        db_session.delete(message)
        db_session.commit()
    return redirect(url_for('admin'))



@app.route('/group/<groupname>/settings', methods=["GET", "POST"])
def group_settings(groupname):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    group = db_session.query(Group).filter_by(groupname=groupname).first()
    if not group:
        flash('Группа не найдена.')
        return redirect(url_for('index'))

    members = db_session.query(User).join(UserGroup, User.username == UserGroup.username).filter(UserGroup.groupname == groupname).all()
    non_members = db_session.query(User).filter(~User.username.in_([member.username for member in members])).all()

    if request.method == "POST":
        add_users = json.loads(request.form.get("addUsers", "[]"))
        remove_users = json.loads(request.form.get("removeUsers", "[]"))

        for username in add_users:
            if not db_session.query(UserGroup).filter_by(groupname=groupname, username=username).first():
                db_session.add(UserGroup(groupname=groupname, username=username))
        
        for username in remove_users:
            user_group = db_session.query(UserGroup).filter_by(groupname=groupname, username=username).first()
            if user_group:
                db_session.delete(user_group)
        
        db_session.commit()
        flash('Настройки группы обновлены.')
        return redirect(url_for('group_settings', groupname=groupname))
    
    return render_template("group_settings.html", groupname=groupname, members=members, non_members=non_members)

@app.route('/group/<groupname>/delete_group', methods=["POST"])
def delete_group(groupname):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db_session.query(UserGroup).filter_by(groupname=groupname).delete()
    db_session.query(Message).filter_by(recipient=groupname).delete()
    db_session.query(Group).filter_by(groupname=groupname).delete()
    db_session.commit()
    flash('Группа и все связанные с ней записи удалены.')
    return redirect(url_for('index'))

@app.route('/group/<groupname>/delete_messages', methods=["POST"])
def delete_group_messages(groupname):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db_session.query(Message).filter_by(recipient=groupname).delete()
    db_session.commit()
    flash('Все сообщения группы удалены.')
    return redirect(url_for('group_settings', groupname=groupname))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
    
