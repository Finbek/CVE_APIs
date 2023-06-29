from flask import Flask,render_template
from database import db
from routes import bp as api_bp

app = Flask(__name__)
app.config.from_pyfile('config.py')
db.init_app(app)

from models import Product, Vulnerability, AffectedVersionsNumber

with app.app_context():
    db.create_all()

app.register_blueprint(api_bp)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4999)
