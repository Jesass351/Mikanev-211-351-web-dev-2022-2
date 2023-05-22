from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/headers')
def headers():
    return render_template("headers.html")
    
@app.route('/args')
def args():
    return render_template("args.html")

@app.route('/cookies')
def cookies():
    resp = make_response(render_template("cookies.html"))
    if 'q' in request.cookies: 
        resp.set_cookie('q', 'qq', expires = 0)
    else:
        resp.set_cookie('q', 'qq')

    return resp

@app.route('/form', methods = ['GET', 'POST'])
def form():
    return render_template("form.html")

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

@app.route('/phone_checker', methods = ['GET', 'POST'])
def phone_checker():
    types_of_error = [
        'Недопустимый ввод. Неверное количество цифр.', 
        'Недопустимый ввод. В номере телефона встречаются недопустимые символы.',
    ]
    allows_chars = [' ', '(', ')', '-', '.', '+', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
    phone_number = None
    error_msg = None
    isnt_valid = False
    
    if request.method == 'POST':
        nums_len = 0
        nums_phone_number = ''
        phone_number = request.form.get('phone_number')
        for num in phone_number:
            if num not in allows_chars:
                return render_template('phone_checker.html', phone_number=phone_number, isnt_valid=True, error_msg=types_of_error[1])
            elif str(num).isdigit():
                nums_phone_number += num
                nums_len += 1
            
        if (phone_number[0] == "+" and phone_number[1] == "7") or phone_number[0] == "8":
            if nums_len != 11:
                return render_template('phone_checker.html', phone_number=phone_number, isnt_valid=True, error_msg=types_of_error[0])
        elif nums_len != 10:
            return render_template('phone_checker.html', phone_number=phone_number, isnt_valid=True, error_msg=types_of_error[0])
        
        if nums_len == 10:
            nums_phone_number = nums_phone_number.rjust(11, "8")
        else:
            nums_phone_number = nums_phone_number.replace("7", "8")
            
        nums_phone_number = f'{nums_phone_number[0]}-{nums_phone_number[1:4]}-{nums_phone_number[4:7]}-{nums_phone_number[7:9]}-{nums_phone_number[9:11]}'
        
        phone_number = nums_phone_number
        

    return render_template('phone_checker.html', phone_number=phone_number, isnt_valid=isnt_valid, error_msg=error_msg)

@app.route('/calc', methods = ['GET', 'POST'])
def calc():
    errormsg = None
    res = None
    if request.method == 'POST': 
        try: 
            op1 = int(request.form.get('operand1'))
            op2 = int(request.form.get('operand2'))
            operator = request.form.get('operator')
            if operator == '+':
                res = op1 + op2
            elif operator == '-':
                res = op1 - op2
            elif operator == '*':
                res = op1 * op2
            elif operator == '/':
                res = op1 / op2
        except ZeroDivisionError: 
            errormsg = "На ноль делить нельзя"
        except ValueError: 
            errormsg = "Вводите только числа"
    return render_template('calc.html', res=res, errormsg=errormsg)