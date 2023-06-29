import os, sys
sys.path.append(os.path.abspath(".."))

import datetime
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


from models import Base, Product, Vulnerability, AffectedVersionsNumber
from pipelines import SQLitePipeline


class SQLitePipelineTestCase(unittest.TestCase):
  def setUp(self):
      engine = create_engine('sqlite:///:memory:')
      Base.metadata.create_all(bind=engine)
      Session = sessionmaker(bind=engine)
      self.session = Session()

  def tearDown(self):
      Base.metadata.drop_all(bind=self.session.bind)
      self.session.close()

  def test_process_item(self):
      pipeline = SQLitePipeline(self.session)
      item = {
          'cvss_score': '4.3',
          'confidentiality_impact': '',
          'integrity_impact': '',
          'availability_impact': '',
          'access_complexity': '',
          'authentication': '',
          'gained_access': 'None',
          'vulnerability_types': 'Cross Site Scripting',
          'vulnerable_products': [{'product_type': 'Application', 'vendor': 'Facturascripts', 'product': 'Facturascripts', 'version': '*', 'update': '*', 'edition': '*', 'language': ''}],
          'affected_versions': [{'vendor': 'Facturascripts', 'product': 'Facturascripts', 'num_versions': '1'}],
          'publish_date': datetime.date(2022, 6, 13),
          'last_update_date': datetime.date(2022, 6, 22)
      }

      pipeline.process_item(item)
      software = self.session.query(Product).filter_by(product='Facturascripts', version='*', vendor='Facturascripts').first()
      vulnerability = self.session.query(Vulnerability).filter_by(cvss_score=4.3).first()
      affected_version = self.session.query(AffectedVersionsNumber).filter_by(affected_version_number=1).first()

      self.assertIsNotNone(software)
      self.assertIsNotNone(vulnerability)
      self.assertIsNotNone(affected_version)
      self.assertEqual(affected_version.vulnerability, vulnerability)
      self.assertEqual(software.affected_versions_number, affected_version)

if __name__ == '__main__':
    unittest.main()
