from database import db, Base


class Product(Base):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    product_type = db.Column(db.String(50), nullable=False)
    vendor = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    update = db.Column(db.String(50), nullable=False)
    edition = db.Column(db.String(50), nullable=False)
    language = db.Column(db.String(50), nullable=False)
    affected_versions_number_id = db.Column(db.Integer, db.ForeignKey(
        'affected_versions_number.id'), nullable=False)

    def __repr__(self):
        return f"<Product(id={self.id}, product_type='{self.product_type}', vendor='{self.vendor}', " \
               f"product='{self.product}', version='{self.version}', update='{self.update}', " \
               f"edition='{self.edition}', language='{self.language}')>"


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    cvss_score = db.Column(db.Float, nullable=False)
    confidentiality_impact = db.Column(db.String(50))
    integrity_impact = db.Column(db.String(50))
    availability_impact = db.Column(db.String(50))
    access_complexity = db.Column(db.String(50))
    authentication = db.Column(db.String(50))
    gained_access = db.Column(db.String(50))
    vulnerability_types = db.Column(db.String(255))
    publish_date = db.Column(db.Date, nullable=False)
    last_update_date = db.Column(db.Date, nullable=False)
    affected_versions = db.relationship(
        'AffectedVersionsNumber', backref='vulnerability')

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, cvss_score={self.cvss_score}, " \
               f"confidentiality_impact='{self.confidentiality_impact}', " \
               f"integrity_impact='{self.integrity_impact}', availability_impact='{self.availability_impact}', " \
               f"access_complexity='{self.access_complexity}', authentication='{self.authentication}', " \
               f"gained_access='{self.gained_access}', vulnerability_types='{self.vulnerability_types}', " \
               f"publish_date='{self.publish_date}', last_update_date='{self.last_update_date}')>"


class AffectedVersionsNumber(Base):
    __tablename__ = 'affected_versions_number'
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey(
        'vulnerabilities.id'), nullable=False)
    affected_version_number = db.Column(db.String(50), nullable=False)
    products = db.relationship('Product', backref='affected_versions_number')

    def __repr__(self):
        return f"<AffectedVersionsNumber(id={self.id}, vulnerability_id={self.vulnerability_id}, " \
            f"affected_version='{self.affected_version_number}')>"
