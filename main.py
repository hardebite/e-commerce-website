
import os
from os import abort
from functools import wraps

# from dominate import document
from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
import stripe
from werkzeug import Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import  *
from sqlalchemy.ext.declarative import declarative_base



stripe_keys = {
  'secret_key': os.environ.get("secret_key"),
  'publishable_key': os.environ.get("publishable_key")
}

stripe.api_key = stripe_keys['secret_key']
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL","sqlite:///E_commerce.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#create the relationship
Base = declarative_base()



##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("Product", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    cart= relationship("Cart",back_populates="cart_author")
    sales= relationship("Sales", back_populates="sales_author")


class Product(db.Model):
    __tablename__ = "products "
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    name = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")

class Sales(db.Model):
        __tablename__ = "sales"
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        sales_author = relationship("User", back_populates="sales")
        Name = db.Column(db.String(250), nullable=False)
        old_price = db.Column(db.Integer, nullable=False)
        new_price = db.Column(db.Integer, nullable=False)
        body = db.Column(db.Text, nullable=False)
        img_url = db.Column(db.String(250), nullable=False)


class Cart(db.Model):
            __tablename__ = "cart "
            id = db.Column(db.Integer, primary_key=True)
            author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
            cart_author = relationship("User", back_populates="cart")
            Name = db.Column(db.String(250), nullable=False)
            price = db.Column(db.Integer, nullable=False)
            quantity=db.Column(db.Integer,nullable=False)
            img_url = db.Column(db.String(250), nullable=False)





class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    products_id = db.Column(db.Integer, db.ForeignKey("products.id"))
    parent_post = relationship("Product", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# db.create_all()


logged_in = False


@app.route('/')
def get_all_posts():
    products = Product.query.all()

    return render_template("index.html", all_products=products, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route("/post/<int:products_id>", methods=["GET", "POST"])

def show_post(products_id):
    requested_product = Product.query.get(products_id)
    comment = Comment.query.all()
    form=CommentForm()
    # print(request.args["number"])

    if form.validate_on_submit():
        print("in")
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
                text=form.comment.data,
                products_id=products_id,
                author_id = current_user.id

            )
        db.session.add(new_comment)
        db.session.commit()




    return render_template("product.html", product=requested_product, current_user=current_user,form = form,comment=comment)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)

@app.route("/cart/<product_id>",methods=["GET","POST"])
def add_cart(product_id):
    cart = Cart.query.all()
    print(product_id)
    print(request.args["number"])
    products_id=product_id
    product_add= Product.query.get(products_id)
    price = product_add.price
    quantity = request.args["number"]
    try:
        product_to_add= Cart(
                        author_id=current_user.id,
                        Name= product_add.name,
                        price=product_add.price,
                        img_url=product_add.img_url,
                        quantity=request.args["number"],
                        )

        db.session.add(product_to_add)
        db.session.commit()
        return redirect(url_for("show_post",products_id=product_id))

    except:
        flash("you have to login to add items to cart")
        return redirect(url_for("show_post",products_id=product_id))

@app.route("/cart",methods=["POST","GET"])
def cart():
    cart = Cart.query.filter_by(author_id=current_user.id)
    total=0
    goods=[]
    img=[]

    for item in cart:
        print(item.Name)
        if item.author_id == current_user.id:
            goods.append(item.Name)
            img.append(item.img_url)
            to = item.price * item.quantity
            total += to
    final_amount= total*100
    return render_template("cart.html", cart =cart , current_user=current_user, total = final_amount,key=stripe_keys['publishable_key'])

@app.route('/charge', methods=['POST'])
def charge():
    # Amount in cents
    total=request.args["amount"]

    # print(product_id)

    customer = stripe.Customer.create(
        email='customer@example.com',
        source=request.form['stripeToken']
    )

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=total,
        currency='usd',
        description='Flask Charge'
    )
    product_to_delete =  Cart.query.filter_by(author_id=current_user.id)
    for items in product_to_delete:
        db.session.delete(items)
        db.session.commit()
    total= float(total)/100

    return render_template('charge.html', amount=total)

@app.route("/delete_cart/<int:products_id>")
@login_required
def delete_cart(products_id):
        post_to_delete = Cart.query.get(products_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('cart'))
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = Product(
                name=form.name.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                price =form.price.data,

            )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("makepost.html", form=form, current_user=current_user)




@app.route("/edit-post/<int:products_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(products_id):

    if admin_only(current_user):
        post = Product.query.get(products_id)
        edit_form = CreatePostForm(
            name=post.name,
            price=post.price,
            img_url=post.img_url,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.name = edit_form.name.data
            post.price = edit_form.price.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id, products_id=products_id))

        return render_template("makepost.html", form=edit_form, is_edit=True, current_user=current_user)

    else:
        return abort(403)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/checkout')
def checkout():
    # total = request.args["total"]

    # print(total)

    return render_template("checkout.html")


@app.route("/delete/<int:products_id>")
@login_required
@admin_only
def delete_post(products_id):
    if admin_only(current_user):
        post_to_delete = Product.query.get(products_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    else:
        return abort(403)



if __name__ == "__main__":
    app.run(debug=True)

