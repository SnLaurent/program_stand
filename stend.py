import re
import os
import sys
import csv
import json
import time
import psutil
import random
import string
import pexpect
import psycopg2
import requests
import threading
import webbrowser
import subprocess
from pathlib import Path
from pexpect import spawn
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtCore import Qt, QProcess, pyqtSlot, QUrl, QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QTableWidget, \
    QTableWidgetItem, QSizePolicy, QProgressDialog, QMessageBox, QLabel, QInputDialog, QDialog, QLineEdit, QGroupBox, QRadioButton, QFileDialog, QTextEdit

class ConnectionDialog(QDialog):
    def __init__(self, parent=None):
        super(ConnectionDialog, self).__init__(parent)

        self.setWindowTitle("Подключение к БД")

        self.host_label = QLabel("Хост:")
        self.host_edit = QLineEdit()

        self.user_label = QLabel("Имя пользователя:")
        self.user_edit = QLineEdit()

        self.password_label = QLabel("Пароль:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.database_label = QLabel("Имя базы данных:")
        self.database_edit = QLineEdit()

        self.connect_button = QPushButton("Подключиться", self)
        self.cancel_button = QPushButton("Отмена", self)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(self.host_label)
        layout.addWidget(self.host_edit)
        layout.addWidget(self.user_label)
        layout.addWidget(self.user_edit)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_edit)
        layout.addWidget(self.database_label)
        layout.addWidget(self.database_edit)
        layout.addWidget(self.connect_button)
        layout.addWidget(self.cancel_button)

        self.connect_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

class OpenVPNDialog(QDialog):
    def __init__(self, parent_app, parent=None):
        super(OpenVPNDialog, self).__init__(parent)

        self.setWindowTitle("Создание сертификатов OpenVPN")
        self.setFixedSize(330, 300)

        self.method_groupbox = QGroupBox("Выбор ввода пароля для сертификатов", self)
        self.keyboard_radio = QRadioButton("С клавиатуры", self)
        self.file_radio = QRadioButton("Из файла", self)

        self.keyboard_radio.setChecked(True)

        self.dir_name_edit = QLineEdit()
        self.dir_name_edit.setPlaceholderText('Выберите директорию...')
        self.dir_btn = QPushButton('Обзор директории')
        self.dir_btn.clicked.connect(self.open_dir_dialog)
        self.certificate_password_edit = QLineEdit()
        self.certificate_password_edit.setPlaceholderText('Введите пароль...')
        self.certificate_password_edit.setEchoMode(QLineEdit.Password)

        self.file_name_edit = QLineEdit()
        self.file_name_edit.setPlaceholderText('Выберите файл с паролем...')
        self.file_btn = QPushButton('Обзор файла')
        self.file_btn.clicked.connect(self.open_file_dialog)

        self.select_button = QPushButton("Создать сертификаты", self)
        self.connected_to_database = parent_app.connected_to_database
        self.select_button.clicked.connect(self.check_and_create_certificate)
        self.total_records = parent_app.total_records

        self.file_radio.toggled.connect(self.file_radio_toggled)
        self.keyboard_radio.toggled.connect(self.keyboard_radio_toggled)

        self.init_ui()

    def file_radio_toggled(self, checked):
        if checked:
            self.setFixedSize(330, 350)
            self.file_name_edit.setVisible(True)
            self.file_btn.setVisible(True)
            self.file_label.setVisible(True)
            self.certificate_password_edit.setVisible(False)

    def keyboard_radio_toggled(self, checked):
        if checked:
            self.setFixedSize(330, 300)
            self.file_name_edit.setVisible(False)
            self.file_btn.setVisible(False)
            self.file_label.setVisible(False)
            self.certificate_password_edit.setVisible(True)

    def open_file_dialog(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if file_name:
            self.file_name_edit.setText(file_name)

    def open_dir_dialog(self):
        dir_name = QFileDialog.getExistingDirectory(self, "Выберите директорию")
        if dir_name:
            self.dir_name_edit.setText(dir_name)

    def check_and_create_certificate(self):

        is_dir_selected = self.dir_name_edit.text().strip() != ""
        is_file_selected = self.file_name_edit.text().strip() != ""
        is_password_entered = self.certificate_password_edit.text().strip() != ""

        if self.file_radio.isChecked():
            if not is_dir_selected and not is_file_selected:
                QMessageBox.warning(None, "Предупреждение", "Выберите директорию для сохранения сертификатов и файл с паролем.")
            elif not is_dir_selected:
                QMessageBox.warning(None, "Предупреждение", "Выберите директорию для сохранения сертификатов.")
            elif not is_file_selected:
                QMessageBox.warning(None, "Предупреждение", "Выберите файл с паролем.")
            else:
                with open(self.file_name_edit.text(),"r") as file:
                    self.certificate_password = file.read().strip()
                    self.dir_name = self.dir_name_edit.text()
                    self.create_certificate(self.dir_name,self.certificate_password)

        if self.keyboard_radio.isChecked():
            if not is_dir_selected and not is_password_entered:
                QMessageBox.warning(None, "Предупреждение", "Выберите директорию для сохранения сертификатов и введите пароль.")
            elif not is_dir_selected:
                QMessageBox.warning(None, "Предупреждение", "Выберите директорию для сохранения сертификатов.")
            elif not is_password_entered:
                QMessageBox.warning(None, "Предупреждение", "Введите пароль для сертификатов")
            else:
                self.certificate_password = self.certificate_password_edit.text()
                self.dir_name = self.dir_name_edit.text()
                self.create_certificate(self.dir_name,self.certificate_password)

    def get_ip_address(self, interface):
        try:
            # Вызываем команду ifconfig для получения информации об IP-адресе
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True, check=True)

            #Используем регулярное выражение для поиска IPv4-адреса
            ip_address_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)

            if ip_address_match:
                return ip_address_match.group(1)
            else:
                return None

        except subprocess.CalledProcessError:
            print(f"Ошибка при выполнении команды ifconfig для интерфейса {interface}")
            return None

    def create_certificate(self, dir_name, certificate_password):

        try:
            interface_name = 'eth0'
            ip_address = self.get_ip_address(interface_name)
            if not ip_address:
                raise Exception("Не удалось получить IP-адрес.")

            count = self.total_records
            for i in range(1, count + 1):
                keys_directory = os.path.join(self.dir_name, f"keys{i}")
                os.makedirs(keys_directory, exist_ok=True)

                os.chdir("/etc/openvpn/easy-rsa")
                print("Current directory: ", os.getcwd())

                # Создаем скрипт expect для автоматизации ввода пароля
                script = f'''
                spawn /etc/openvpn/easy-rsa/easyrsa build-client-full client{i} nopass
                expect "Enter pass phrase for*"
                send "{certificate_password}\\r"
                expect eof
                '''

                process = subprocess.Popen(['expect', '-'], stdin=subprocess.PIPE)
                process.communicate(script.encode())

                subprocess.run(["cp", f"/etc/openvpn/easy-rsa/pki/issued/client{i}.crt",
                            f"/etc/openvpn/easy-rsa/pki/private/client{i}.key",
                            "/etc/openvpn/easy-rsa/pki/ca.crt",
                            "/etc/openvpn/easy-rsa/pki/ta.key", keys_directory])

                os.chmod(keys_directory, 0o777)

                with open(f"{keys_directory}/config_client{i}.ovpn", "a") as config_file:
                    config_file.write(f"""
client
resolv-retry infinite
nobind
remote {ip_address} 1194
proto udp
dev tun
ca ca.crt
cert client{i}.crt
key client{i}.key
tls-client
tls-auth ta.key 1
float
keepalive 10 120
persist-key
persist-tun
tun-mtu 1500
mssfix 1620
cipher AES-256-GCM
remote-cert-tls server
verb 6
""")

            print("Certificates created successfully!")
            QMessageBox.information(None, "Успех", "Создание сертификатов OpenVPN прошло успешно!")
        except Exception as e:
            print(f"Error creating certificates: {str(e)}")
            QMessageBox.warning(None, "Ошибка", "Ошибка при создании сертификатов OpenVPN")

    def init_ui(self):
        layout = QVBoxLayout(self)

        method_layout = QVBoxLayout(self.method_groupbox)
        method_layout.addWidget(self.keyboard_radio)
        method_layout.addWidget(self.file_radio)
        method_layout.addWidget(QLabel('Директория для сохранения сертификатов:'))
        method_layout.addWidget(self.dir_name_edit)
        method_layout.addWidget(self.dir_btn)
        method_layout.addWidget(self.certificate_password_edit)
        self.file_label = QLabel('Файл с паролем:')
        method_layout.addWidget(self.file_label)
        method_layout.addWidget(self.file_name_edit)
        method_layout.addWidget(self.file_btn)
        self.file_name_edit.setVisible(False)
        self.file_btn.setVisible(False)
        self.file_label.setVisible(False)

        layout.addWidget(self.method_groupbox)
        layout.addWidget(self.select_button)


class CTFdDialog(QDialog):
    def __init__(self, parent=None):
        super(CTFdDialog, self).__init__(parent)

        self.setWindowTitle("Администрирование CTFd")
        self.setFixedSize(400, 450)

        self.token_groupbox = QGroupBox("Ввод токена доступа", self)
        #self.keyboard_radio = QRadioButton("С клавиатуры", self)
        #self.file_radio = QRadioButton("Из файла", self)

        #self.keyboard_radio.setChecked(True)
        #self.file_radio.toggled.connect(self.file_radio_toggled)
        #self.keyboard_radio.toggled.connect(self.keyboard_radio_toggled)

        # self.ctfd_token_edit = QLineEdit()
        # self.ctfd_token_edit.setPlaceholderText('Введите токен доступа...')

        self.file_token_edit = QLineEdit()
        self.file_token_edit.setPlaceholderText('Выберите файл с токеном...')
        self.file_token_btn = QPushButton('Выбрать файл')
        self.file_token_btn.clicked.connect(self.open_file_dialog)

        self.task_value_edit = QLineEdit()
        self.task_value_edit.setPlaceholderText('Введите количество баллов')

        self.create_users_btn = QPushButton("Создать пользователей")
        self.create_users_btn.clicked.connect(self.check_and_create_users)

        self.create_task_btn = QPushButton("Создать задание")
        self.create_task_btn.clicked.connect(self.check_and_create_task)

        self.open_ctfd_btn = QPushButton("Открыть CTFd")
        self.open_ctfd_btn.clicked.connect(self.open_ctfd)

        self.log_textedit = QTextEdit()
        self.log_textedit.setReadOnly(True)

        # Параметры подключения к CTFd API
        #self.CTFD_TOKEN = self.ctfd_token_edit.text()
        self.CTFD_URL = "http://localhost:8000/api/v1"
        self.directory_path = '/home/bakulin/info'

        # Добавление CSV файла для считывания данных
        self.CSV_FILE_USERS = "users_data.csv"
        self.CSV_FILE_FLAGS = "flags_data.csv"

        self.init_ui()

    def open_file_dialog(self):
        token_file, _ = QFileDialog.getOpenFileName(self, "Выберите файл с токеном")
        if token_file:
            self.file_token_edit.setText(token_file)

    def check_and_create_users(self):
        token_file_dialog = self.file_token_edit.text().strip() != ""
        if not token_file_dialog:
            QMessageBox.warning(self, "Предупреждение", "Выберите файл с токеном.")
        else:
            with open(self.file_token_edit.text(),"r") as file:
                CTFD_TOKEN = file.read().strip()
                self.create_users(CTFD_TOKEN, self.CTFD_URL)

    def check_and_create_task(self):
        token_file_dialog = self.file_token_edit.text().strip() != ""
        task_value_none = self.task_value_edit.text().strip() != ""
        if not token_file_dialog and not task_value_none:
            QMessageBox.warning(self, "Предупреждение", "Выберите файл с токеном и введите количество баллов для заданий.")
        elif not token_file_dialog:
            QMessageBox.warning(self, "Предупреждение", "Выберите файл с токеном.")
        elif not task_value_none:
            QMessageBox.warning(self, "Предупреждение", "Введите количество баллов для заданий.")
        else:
            task_value = self.task_value_edit.text()
            with open(self.file_token_edit.text(),"r") as file:
                CTFD_TOKEN = file.read().strip()
                self.create_task(CTFD_TOKEN, self.CTFD_URL, task_value)

    def generate_password(self, length=8):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(alphabet) for _ in range(length))
        return password

    def create_users(self, CTFD_TOKEN, CTFD_URL):
        self.log_textedit.clear()
        # Создание API сессии
        CTFD_URL = CTFD_URL.strip("/")
        s = requests.Session()
        s.headers.update({"Authorization": f"Token {CTFD_TOKEN.strip()}"})
        base_directory = "/home/bakulin/control"
        os.makedirs(base_directory, exist_ok=True)
        with open(self.CSV_FILE_USERS, 'r') as file:
            reader = csv.reader(file)
            header = next(reader)  # Пропустить заголовок

            for row in reader:
                password = self.generate_password()
                name, email, = row
                user_data = {
                    "name": name,
                    "email": email,
                    "password": password,
                    "type": "user",
                    "verified": False,
                    "hidden": False,
                    "banned": False,
                    "fields": []
                    }

                # Отправка POST-запроса для создания аккаунта
                r = s.post(f"{CTFD_URL}/users", json=user_data, headers={"Content-Type": "application/json"})


                folder_name = os.path.join(base_directory, f'{name}')
                os.makedirs(folder_name, exist_ok=True)

                file_path = os.path.join(folder_name, f'log_pass_{name}')
                with open(file_path, "w") as file:
                    file.write(f"Логин: {email}\n")
                    file.write(f"Пароль: {password}\n")

                log_message = f"Аккаунт участника '{name}' успешно создан"
                self.log_textedit.append(log_message)

            # Проверка успешности запроса
            if r.status_code == 200:
                QMessageBox.information(self, "Успех", "Аккаунты пользователей CTFd успешно созданы!")
            else:
                QMessageBox.warning(self, "Ошибка", f"Ошибка при создании аккаунтов пользователей. Код ошибки: {r.status_code}")

    def check_files_existence(self, directory_path):
        files_exist = False
        for root, dirs, files in os.walk(directory_path):
            for dir in dirs:
                file_path = os.path.join(root, dir, 'generated_phrase.txt')
                if os.path.exists(file_path):
                    files_exist = True
                    break
        return files_exist

    def create_task(self, CTFD_TOKEN, CTFD_URL, task_value):
        self.log_textedit.clear()
        # Создание API сессии
        CTFD_URL = CTFD_URL.strip("/")
        s = requests.Session()
        s.headers.update({"Authorization": f"Token {CTFD_TOKEN.strip()}"})

        success_flag = True

        if not self.check_files_existence(self.directory_path):
            QMessageBox.warning(self, "Ошибка", "Создайте практические задания")
            return

        with open(self.CSV_FILE_USERS, 'r') as file:
            reader = csv.reader(file)
            header = next(reader)  # Пропустить заголовок

            for user_row in reader:
                name, email = user_row

                # Создание задания для пользователя
                challenge_data = {
                    "name": f"Задание для пользователя '{name}'",
                    "description": f"Администрирование ОССН Astra Linux SE",
                    "category": "Категория пользователя",
                    "value": task_value,
                    "type": "standard",
                    "state": "visible"
                }

                # Создание задания в CTFd
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {CTFD_TOKEN.strip()}"
                }

                response = requests.post(f"{CTFD_URL}/challenges", headers=headers, data=json.dumps(challenge_data))

                if response.status_code != 200:
                    success_flag = False
                    QMessageBox.warning(self, "Ошибка", f"Ошибка при создании заданий. Код ошибки: {response.status_code}")
                    break

                # Retrieve the created challenge ID
                response_data = response.json()
                challenge_id = response_data['data']['id']
                log_message = f"Задание для пользователя '{name}' c номером {challenge_id} создано"
                self.log_textedit.append(log_message)

                # Open the flags CSV file and iterate over its rows
                with open(self.CSV_FILE_FLAGS, "r") as flags_file:
                    flags_reader = csv.reader(flags_file)
                    next(flags_reader)  # Пропустить заголовок
                    for flag_row in flags_reader:
                        flag_challenge_id, flag = flag_row
                        if flag_challenge_id == str(challenge_id):

                            # Add flag to the challenge
                            flag_data = {
                                "challenge": challenge_id,
                                "type": "static",
                                "content": flag,
                                "data": flag
                                }
                            flag_response = requests.post(f"{CTFD_URL}/flags", json=flag_data, headers=headers)

                            if flag_response.status_code != 200:
                                success_flag = False
                                log_message = f"Ошибка при добавлении флага к заданию с номером '{challenge_id}': {flag_response.text}"
                                self.log_textedit.append(log_message)
                            else:
                                log_message = f"Флаг успешно добавлен к заданию с номером '{challenge_id}'"
                                self.log_textedit.append(log_message)

        if success_flag:
            QMessageBox.information(self, "Успех", "Задания для пользователей успешно созданы!")
        else:
            QMessageBox.warning(self, "Ошибка", f"Ошибка при создании заданий. Код ошибки: {response.status_code}")

    def open_ctfd(self):
        QDesktopServices.openUrl(QUrl("http://127.0.0.1:8000"))

    def init_ui(self):
        layout = QVBoxLayout(self)

        token_layout = QVBoxLayout(self.token_groupbox)
        # token_layout.addWidget(self.keyboard_radio)
        # token_layout.addWidget(self.file_radio)
        # token_layout.addWidget(self.ctfd_token_edit)
        token_layout.addWidget(self.file_token_edit)
        token_layout.addWidget(self.file_token_btn)

        layout.addWidget(self.token_groupbox)
        layout.addWidget(self.task_value_edit)
        layout.addWidget(self.create_users_btn)
        layout.addWidget(self.create_task_btn)
        layout.addWidget(self.open_ctfd_btn)
        layout.addWidget(self.log_textedit)

        self.file_token_edit.setVisible(True)
        self.file_token_btn.setVisible(True)

class DatabaseApp(QWidget):
    def __init__(self):
        super().__init__()

        # Устанавливаем фиксированный размер окна
        self.setFixedSize(820, 700)

        # Создаем кнопки
        self.database_button = QPushButton("База данных", self)
        self.openvpn_button = QPushButton("Защищенное соединение", self)
        self.ctfd_button = QPushButton("Сервис верификации", self)
        self.task_button = QPushButton("Практические задания", self)

        self.start_webserver_button = QPushButton("Включить", self)
        self.stop_webserver_button = QPushButton("Выключить", self)
        self.start_database_server_button = QPushButton("Включить", self)
        self.stop_database_server_button = QPushButton("Выключить", self)

        self.log_textedit = QTextEdit()
        self.log_textedit.setReadOnly(True)

        self.web_server_status_color_indicator = QLabel()
        self.web_server_status_color_indicator.setFixedSize(80, 30)

        self.database_server_status_color_indicator = QLabel()
        self.database_server_status_color_indicator.setFixedSize(80,30)

        self.record_count_label = QLabel("Количество записей: 0", self)

        # Создаем группу кнопок и устанавливаем ей заголовок
        self.buttons_groupbox = QGroupBox("Управление сервисами")
        self.buttons_groupbox.setFixedSize(800, 80)
        top_layout = QHBoxLayout(self.buttons_groupbox)
        top_layout.addWidget(self.database_button)
        top_layout.addWidget(self.openvpn_button)
        top_layout.addWidget(self.ctfd_button)
        top_layout.addWidget(self.task_button)

        self.webserver_group = QGroupBox("Управление веб-сервером")
        self.webserver_group.setFixedSize(360, 70)
        webserver_layout = QHBoxLayout()
        webserver_layout.addWidget(self.start_webserver_button)
        webserver_layout.addWidget(self.stop_webserver_button)
        webserver_layout.addWidget(self.web_server_status_color_indicator)
        self.webserver_group.setLayout(webserver_layout)

        self.database_server_group = QGroupBox("Управление сервером БД")
        self.database_server_group.setFixedSize(360, 70)
        database_layout = QHBoxLayout()
        database_layout.addWidget(self.start_database_server_button)
        database_layout.addWidget(self.stop_database_server_button)
        database_layout.addWidget(self.database_server_status_color_indicator)
        self.database_server_group.setLayout(database_layout)

        self.server_group = QGroupBox()
        self.server_group.setFixedSize(800, 85)
        server_layout = QHBoxLayout()
        server_layout.addWidget(self.webserver_group)
        server_layout.addWidget(self.database_server_group)
        self.server_group.setLayout(server_layout)

        # Создаем вертикальный менеджер компоновки для таблицы
        self.database_content = self.create_table()
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.buttons_groupbox)
        main_layout.addWidget(self.server_group)
        main_layout.addWidget(self.database_content)
        main_layout.addWidget(self.record_count_label)
        main_layout.addWidget(self.log_textedit)

        # Устанавливаем вертикальный менеджер компоновки в качестве основного
        self.setLayout(main_layout)

        # Подключаем обработчики событий
        self.database_button.clicked.connect(self.show_database_dialog)
        self.openvpn_button.clicked.connect(self.show_openvpn_dialog)
        self.ctfd_button.clicked.connect(self.show_ctfd_dialog)
        self.task_button.clicked.connect(self.show_task_dialog)
        self.start_webserver_button.clicked.connect(self.start_webserver)
        self.stop_webserver_button.clicked.connect(self.stop_webserver)
        self.start_database_server_button.clicked.connect(self.start_database_server)
        self.stop_database_server_button.clicked.connect(self.stop_database_server)

        # Создаем процесс для запуска XAMPP
        self.xampp_process = QProcess(self)

        # Инициализируем количество записей
        self.total_records = 0

        # Создаем флаг, индицирующий подключение к БД
        self.connected_to_database = False
        self.update_server_status()

    def update_server_status(self):
        apache2_running = self.is_process_running_for_user('apache2', 'root')
        if apache2_running:
            self.web_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Веб-сервер Apache2 включен \n"
            self.log_textedit.append(log_message)

        else:
            self.web_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Веб-сервер Apache2 выключен \n"
            self.log_textedit.append(log_message)

        postgres_running = self.is_process_running_for_user('postgres', 'postgres')
        if postgres_running:
            self.database_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Сервер PostgreSQL включен \n"
            self.log_textedit.append(log_message)
        else:
            self.database_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Сервер PostgreSQL выключен \n"
            self.log_textedit.append(log_message)

    #Проверка запуска процесса базы данной
    def is_process_running_for_user(self, process_name, username):
        for process in psutil.process_iter(['pid', 'name', 'username']):
            if process.info['name'].lower() == process_name.lower() and process.info['username'] == username:
                return True
        return False

    #Cоздаем таблицу и устанавливаем размеры столбцов
    def create_table(self):
        table = QTableWidget()
        table.setFixedSize(800, 265)
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Фамилия", "Эл. почта", "Логин", "Время регистрации", "IP-адрес"])
        table.setColumnWidth(0, 130)
        table.setColumnWidth(1, 180)
        table.setColumnWidth(2, 130)
        table.setColumnWidth(3, 180)
        table.setColumnWidth(4, 150)
        return table

    def show_database_dialog(self):
        # Проверяем, запущен ли процесс
        postgres_running = self.is_process_running_for_user('postgres', 'postgres')

        if not postgres_running:
            QMessageBox.warning(self, "Предупреждение", "Необходимо включить сервер PostgreSQL.")
        else:
            self.show_connection_dialog()

    def start_webserver(self):
        subprocess.run(['systemctl','start','apache2'], check=True)
        apache2_running = self.is_process_running_for_user('apache2', 'root')
        if apache2_running:
            self.web_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Веб-сервер Apache2 включен \n"
            self.log_textedit.append(log_message)

        else:
            self.web_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Веб-сервер Apache2 выключен \n"
            self.log_textedit.append(log_message)

    def stop_webserver(self):
        subprocess.run(['systemctl','stop','apache2'], check=True)
        apache2_running = self.is_process_running_for_user('apache2', 'root')
        if not apache2_running:
            self.web_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Веб-сервер Apache2 выключен \n"
            self.log_textedit.append(log_message)
        else:
            self.web_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Веб-сервер Apache2 включен \n"
            self.log_textedit.append(log_message)

    def start_database_server(self):
        subprocess.run(['systemctl','start','postgresql'], check=True)
        postgres_running = self.is_process_running_for_user('postgres', 'postgres')
        if postgres_running:
            self.database_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Cервер БД PostgreSQL включен \n "
            self.log_textedit.append(log_message)
        else:
            self.database_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Cервер БД PostgreSQL выключен \n"
            self.log_textedit.append(log_message)

    def stop_database_server(self):
        subprocess.run(['systemctl','stop','postgresql'], check=True)
        time.sleep(1)
        postgres_running = self.is_process_running_for_user('postgres', 'postgres')
        if not postgres_running:
            self.database_server_status_color_indicator.setStyleSheet("background-color: red")
            log_message = f"Cервер БД PostgreSQL выключен \n"
            self.log_textedit.append(log_message)
        else:
            self.database_server_status_color_indicator.setStyleSheet("background-color: green")
            log_message = f"Cервер БД PostgreSQL включен \n"
            self.log_textedit.append(log_message)

    #Диалоговое окно для подключения к базе данных
    def show_connection_dialog(self):
        connection_dialog = ConnectionDialog(self)
        if connection_dialog.exec_() == QDialog.Accepted:
            host = connection_dialog.host_edit.text()
            user = connection_dialog.user_edit.text()
            password = connection_dialog.password_edit.text()
            database = connection_dialog.database_edit.text()
            self.connect_to_database(host, user, password, database)

    #Подключение к базе данных
    def connect_to_database(self, host, user, password, database):
        self.database_content.setRowCount(0)

        try:
            db_connection = psycopg2.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )

            # Создаем курсор для выполнения SQL-запросов
            with db_connection.cursor() as cursor:
                sql_query = "SELECT name,email,login,last_enter,last_ip FROM users"
                cursor.execute(sql_query)
                result = cursor.fetchall()

                # Устанавливаем количество строк и столбцов в QTableWidget
                self.database_content.setRowCount(len(result))
                self.database_content.setColumnCount(len(result[0]))

                # Заполняем QTableWidget данными из результата запроса
                for i, row in enumerate(result):
                    for j, value in enumerate(row):
                        item = QTableWidgetItem(str(value))
                        item.setTextAlignment(Qt.AlignCenter)
                        self.database_content.setItem(i, j, item)

                # Выполняем запрос для получения общего количества записей
                count_query = "SELECT COUNT(*) FROM users"
                cursor.execute(count_query)
                self.total_records = cursor.fetchone()[0]

                # Обновляем QLabel с текущим общим количеством записей
                self.record_count_label.setText(f"Зарегистрировано участников: {self.total_records}")
                self.record_count_label.setVisible(True)

                # Создание CSV файла и запись данных в него
                csv_filename = "users_data.csv"

                with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
                    csv_writer = csv.writer(csv_file)

                    # Запись заголовков
                    csv_writer.writerow(["Name", "Email"])

                    #Заполнение файла
                    for row in result:
                        csv_writer.writerow([row[0],row[1]])

            # Set the flag to indicate successful connection
            self.connected_to_database = True

            # Выводим сообщение об успешном подключении и заполнении таблицы
            QMessageBox.information(self, "Успех", f"Подключение к базе данных и заполнение таблицы выполнено успешно! \n")
            log_message = f'Подключение к БД Установлено. Создан файл {csv_filename}'
            self.log_textedit.append(log_message)

        except psycopg2.Error as e:
            QMessageBox.warning(self, "Ошибка", f"Ошибка при подключении к базе данных:\n{str(e)}")

    def show_openvpn_dialog(self):
        if self.connected_to_database:
            dialog = OpenVPNDialog(self)
            dialog.exec()
        else:
            QMessageBox.warning(self, "Предупреждение", "Необходимо подключиться к базе данных.")

    def show_ctfd_dialog(self):
        if self.connected_to_database:
            ctfd_dialog = CTFdDialog(self)
            ctfd_dialog.exec_()
        else:
            QMessageBox.warning(self, "Предупреждение", "Необходимо подключиться к базе данных.")

    def show_task_dialog(self):
        if self.connected_to_database:
            os.system("python3 qt.py")
        else:
            QMessageBox.warning(self, "Предупреждение", "Необходимо подключиться к базе данных.")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = DatabaseApp()
    window.setWindowTitle("Программный стенд автоматизированного контроля навыков администрирования "
                          "ОССН Astra Linux SE")
    window.show()

    sys.exit(app.exec_())
