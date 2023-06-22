from flask import Blueprint, render_template, request, flash, redirect, url_for
from app import db
from models import Course, Category, User, Review
from tools import CoursesFilter, ImageSaver
from sqlalchemy import desc


bp = Blueprint('courses', __name__, url_prefix='/courses')

COURSE_PARAMS = [
    'author_id', 'name', 'category_id', 'short_desc', 'full_desc'
]

def params():
    return { p: request.form.get(p) for p in COURSE_PARAMS }

def search_params():
    return {
        'name': request.args.get('name'),
        'category_ids': [x for x in request.args.getlist('category_ids') if x],
    }

@bp.route('/')
def index():
    courses = CoursesFilter(**search_params()).perform()
    pagination = db.paginate(courses)
    courses = pagination.items
    categories = db.session.execute(db.select(Category)).scalars()
    return render_template('courses/index.html',
                           courses=courses,
                           categories=categories,
                           pagination=pagination,
                           search_params=search_params())

@bp.route('/new')
def new():
    categories = db.session.execute(db.select(Category)).scalars()
    users = db.session.execute(db.select(User)).scalars()
    return render_template('courses/new.html',
                           categories=categories,
                           users=users)

@bp.route('/create', methods=['POST'])
def create():

    f = request.files.get('background_img')
    if f and f.filename:
        img = ImageSaver(f).save()

    course = Course(**params(), background_image_id=img.id)
    db.session.add(course)
    db.session.commit()

    flash(f'Курс {course.name} был успешно добавлен!', 'success')

    return redirect(url_for('courses.index'))

@bp.route('/<int:course_id>')
def show(course_id):
    course = db.get_or_404(Course, course_id)
    reviews = db.session.execute(db.select(Review).filter_by(course_id=course_id).order_by(desc(Review.created_at)).limit(5)).scalars()
    return render_template('courses/show.html', course=course, reviews=reviews)

@bp.route('/<int:course_id>/reviews')
def show_reviews(course_id):
    course = db.get_or_404(Course, course_id)
    reviews = db.session.execute(db.select(Review).filter_by(course_id=course_id).order_by(desc(Review.created_at))).scalars()
    
    return render_template('courses/show_reviews.html', course=course, reviews=reviews)
