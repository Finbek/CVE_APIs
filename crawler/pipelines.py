from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import Product, Vulnerability, AffectedVersionsNumber
import os
import sys
sys.path.append(os.path.abspath(".."))


class SQLitePipeline:
    def __init__(self, session=None):
        if session == None:
            database_path = os.path.abspath('../instance/database.db')
            engine = create_engine(f'sqlite:///{database_path}')
            Session = sessionmaker(bind=engine)
            self.session = Session()
        else:
            self.session = session

    def close_spider(self, spider=None):
        self.session.commit()
        self.session.close()

    def process_item(self, item, spider=None):
        vulnerability = Vulnerability(
            cvss_score=item['cvss_score'],
            confidentiality_impact=item['confidentiality_impact'],
            integrity_impact=item['integrity_impact'],
            availability_impact=item['availability_impact'],
            access_complexity=item['access_complexity'],
            authentication=item['authentication'],
            gained_access=item['gained_access'],
            vulnerability_types=item['vulnerability_types'],
            publish_date=item['publish_date'],
            last_update_date=item['last_update_date']
        )
        self.session.add(vulnerability)
        self.session.commit()
        products = {}

        for el in item['affected_versions']:
            affected_versions = AffectedVersionsNumber(
                vulnerability_id=vulnerability.id,
                affected_version_number=el['num_versions']
            )
            self.session.add(affected_versions)
            self.session.commit()
            products[(el['product'], el['vendor'])] = affected_versions

        for el in item['vulnerable_products']:
            # potential bug here, it's possible to receive the corrupted data, in which case the product, vendor may differ from
            # version_number, version_update, version_edition, version_language. Need handle latter
            if (el['product'], el['vendor']) not in products:
                continue
            affected_versions_number = products[(el['product'], el['vendor'])]
            product = Product(
                product_type=el['product_type'],
                vendor=el['vendor'],
                product=el['product'],
                version=el['version'],
                update=el['update'],
                edition=el['edition'],
                language=el['language'],
                # Use affected_versions_number.id instead of affected_versions_number
                affected_versions_number_id=affected_versions_number.id
            )
            self.session.add(product)
            self.session.commit()
        return item
