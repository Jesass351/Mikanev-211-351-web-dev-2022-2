SECRET_KEY = 'e341e6698cb20dd889d040a9be7d5fc129cb06255f349bd6ea3f901afe8d61b4'

MYSQL_USER = 'std_2033_lab4'
MYSQL_PASSWORD = 'Artem2558'
MYSQL_HOST = 'std-mysql.ist.mospolytech.ru'
MYSQL_DATABASE = 'std_2033_lab4'


PERMITTED_CHARS_LOGIN = "abcdefghijklmnopqrstuvwxyz0123456789"
PERMITTED_CHARS_PASSWORD = '''abcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя1234567890~!?@#$%^&*_-+()[]{}></\|"'.,:;'''

ERRORS_USERS = {
        "empty_login": "Логин не может быть пустым",
        "empty_password": "Пароль не может быть пустым",
        "empty_last_name": "Фамилия не может быть пустой",
        "empty_first_name": "Имя не может быть пустым",
        "login_too_small": "Логин должен содержать не менее 5 символов",
        "login_incorrect_chars": "Логин должен содержать только латинские букв и цифры",
        "password_too_small": "Пароль должен быть не менее 8 символов",
        "password_too_big": "Пароль должен быть не более 128 символов",
        "password_has_spaces": "Пароль не может содержать пробелов",
        "password_incorrect_chars": '''Пароль должен состоять из латинских или кириллических букв, содержать только арабские цифры и допустимые символы: ~!?@#$%^&*_-+()[]{}></\|"'.,:;''',
        "password_no_upper": "Пароль должен содержать как минимум одну заглавную букву",
        "password_no_lower": "Пароль должен содержать как минимум одну строчную букву",
        "password_no_digit": "Пароль должен содержать как минимум одну цифру",
        "incorrect_password": "Неверный пароль",
        "incorrect_same_password": "Пароли должны совпадать"
    }