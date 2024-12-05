import pickle
import sys
import os
import getpass
import hashlib
from cryptography.fernet import Fernet
import base64
import random


class Password:
    def __init__(self, encrypted_login: bytes, encrypted_password: bytes):
        self.encrypted_login = encrypted_login
        self.encrypted_password = encrypted_password

    def __getstate__(self) -> dict:
        return {"param1": self.encrypted_login, "param2": self.encrypted_password}

    def __setstate__(self, state: dict):
        self.encrypted_login = state["param1"]
        self.encrypted_password = state["param2"]


def save_to_bin(filename: str, passwords: dict):
    with open(filename, "wb") as file:
        pickle.dump(passwords, file)


def load_from_bin(filename: str) -> dict:
    if not os.path.exists(filename) or os.path.getsize(filename) == 0:
        return {}
    try:
        with open(filename, "rb") as file:
            return pickle.load(file)
    except pickle.UnpicklingError:
        print('Файл повреждён')
        sys.exit()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_key(master_password: str) -> bytes:
    """Генерирует ключ для Fernet на основе мастер-пароля."""
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())


def encrypt_data(key: bytes, data: str) -> bytes:
    """Шифрует данные (логин или пароль) с использованием ключа."""
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())


def decrypt_data(key: bytes, encrypted_data: bytes) -> str:
    """Расшифровывает данные (логин или пароль) с использованием ключа."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()


def authenticate(master_hash):
    user_password = getpass.getpass("Введите мастер-пароль: ")
    if hash_password(user_password) == master_hash:
        return user_password
    else:
        print("Неверный мастер-пароль!")
        sys.exit()

HELP_TEXT = '''Использование:
    new - создать новый пароль
    cat - вывести список текущих паролей
    create - создать новую базу паролей (если файл не существует)
    "-f [Название файла]" в конце каждой команды для работы с базами с другим именем
    
new:
    passbin.py new [Имя сервиса] [Логин] [Пароль] - Добавить новый пароль в базу
    passbin.py new [Имя сервиса] [Логин] -g[Длина] - Сгенерировать случайный пароль указанной длины (по умолчанию 16 символов)

cat:
    passbin.py cat [Имя сервиса] - Просмотр пароля для указанного сервиса
    passbin.py cat  - Просмотр всех сохранёных паролей

create:
    passbin.py create - Создать новую базу паролей с мастер-паролем (если файл не существует)'''

NEW_TEXT = 'Ошибка: недостаточно аргументов. Используйте:\n\tpassbin.py new [Имя сервиса] [Логин] [Пароль]'
FILE_ERROR_TEXT = 'Файл некорректен, либо не существует, создайте базу с паролями!'

def create_base():
    master_password = getpass.getpass()
    master_hash = hash_password(master_password)
    password_list['MASTER'] = master_hash
    save_to_bin(filename, password_list)
    print("Мастер-пароль успешно установлен!")
    sys.exit()

def main(filename:str='paroli.pb'):
    try:
        if filename[-3:] != '.pb':
            filename = filename + '.pb'

        if len(sys.argv) < 2 or sys.argv[1] not in ['cat', 'new', 'create']:
            print(HELP_TEXT)
            sys.exit()
        if sys.argv[1] == 'new' and len(sys.argv) < 4:
            print(HELP_TEXT)
            sys.exit()
        if sys.argv[1] == 'cat' and not os.path.exists(filename):
            print(f'Файл {filename} не существует')
            sys.exit()
        

        if sys.argv[1] == 'create':
            print('Введите пароль для шифрования новой базы:')
            password = hash_password(getpass.getpass())
            password_list = {'MASTER': password}
            save_to_bin(filename, password_list)
            print('База успешно создана!')
            return
        else:
            password_list = load_from_bin(filename)

        if 'MASTER' not in password_list:
            print(f'{filename}: {FILE_ERROR_TEXT}')
            sys.exit()
        
        master_password = authenticate(password_list['MASTER'])   
        key = generate_key(master_password)

        if sys.argv[1] == 'new':
            if sys.argv[2] == 'MASTER':
                print('Имя \'MASTER\' зарезервировано, его нельзя использовать, выберите другое.')
                sys.exit()

            name = sys.argv[2]
            login = sys.argv[3]

            if sys.argv[4].startswith('-g'):
                try:
                    pass_len = int(sys.argv[4][2:]) if len(sys.argv[4]) > 2 else 16
                    password_input = generate_password(pass_len)
                    print(f'Сгенерированный пароль для "{name}": {password_input}')
                except ValueError:
                    print('Неверный формат длины пароля. Используйте -g[длина], например -g16.')
                    sys.exit()
            else:
                password_input = sys.argv[4]

            encrypted_login = encrypt_data(key, login)
            encrypted_password = encrypt_data(key, password_input)
            password = Password(encrypted_login, encrypted_password)
            password_list[name] = password
            save_to_bin(filename, password_list)
            print(f'Пароль для "{name}" успешно добавлен!')

        elif sys.argv[1] == 'cat':

            try:
                if sys.argv[2] == '-f': raise IndexError
                password_to_watch = sys.argv[2]
                for name, password in password_list.items():
                    if name != 'MASTER' and name.lower() == password_to_watch.lower():
                        decrypted_login = decrypt_data(key, password.encrypted_login)
                        decrypted_password = decrypt_data(key, password.encrypted_password)
                        print(f'{name} - {decrypted_login} - {decrypted_password}')
                        break
                else:
                    print(f'Данные для {password_to_watch} не найдены')
            except IndexError:
                if len(password_list) <= 1:
                    print('Нет сохранённых паролей.')
                else:
                    print("Список сохранённых паролей:")
                    for name, password in password_list.items():
                        if name != 'MASTER':
                            decrypted_login = decrypt_data(key, password.encrypted_login)
                            decrypted_password = decrypt_data(key, password.encrypted_password)
                            print(f'{name} - {decrypted_login} - {decrypted_password}')
    except KeyboardInterrupt:
        print('Goodbye')

def generate_password(pass_len: int = 16) -> str:
    """Генерирует случайный пароль указанной длины."""
    symbols = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_=+!@#$%^&*()[{}\\|/?.>,<`~"№;:]'
    password = ''.join(random.choice(symbols) for _ in range(pass_len))
    return password



if __name__ == '__main__':
    if '-f' in sys.argv:
        try:
            filename = str(sys.argv[sys.argv.index('-f') + 1])
            main(filename=filename)
        except:
            print('Ошибочка')
    else:
        main()
