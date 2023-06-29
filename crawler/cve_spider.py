import scrapy
from datetime import datetime

class Spider(scrapy.Spider):
  name = 'cve_spider'
  basic_url = 'https://www.cvedetails.com'
  start_urls = [
    basic_url+"/vulnerability-list/year-2022/vulnerabilities.html",
    basic_url+"/vulnerability-list/year-2023/vulnerabilities.html",
  ]



  #Parsing start_url sets
  def parse(self, response):
    current_page= 1
    while True:
      link_xpath = "//div[@id='pagingb']/a[contains(@title, 'Go to page') and contains(text(), '{}')]".format(current_page)
      link_element = response.xpath(link_xpath).get()
      if link_element:
        link_url = response.urljoin(response.xpath(link_xpath + "/@href").get())
        current_page += 1
        yield scrapy.Request(link_url, callback=self.parse_page)
      else:
        break

  #Parsing each page of the start url
  def parse_page(self, response):
    trs = response.xpath("//div[@id='searchresults']/table[@class='searchresults sortable']/tr[contains(@class, 'srrowns')]")
    for tr in trs:
      link = tr.xpath("td[2]/a/@href").extract_first()
      if link:
        yield response.follow(self.basic_url+link, self.cve_parse)

  #Parsing each CVE page
  def cve_parse(self, response):
    selector = scrapy.Selector(response)
    # Extract CVE info
    cvss_score = selector.xpath('//table[@id="cvssscorestable"]//div[contains(@class, "cvssbox")]/text()').get()
    confidentiality_impact = selector.xpath('//th[contains(text(), "Confidentiality Impact")]/following-sibling::td/span/text()').get()
    integrity_impact = selector.xpath('//th[contains(text(), "Integrity Impact")]/following-sibling::td/span/text()').get()
    availability_impact = selector.xpath('//th[contains(text(), "Availability Impact")]/following-sibling::td/span/text()').get()
    access_complexity = selector.xpath('//th[contains(text(), "Access Complexity")]/following-sibling::td/span/text()').get()
    authentication = selector.xpath('//th[contains(text(), "Authentication")]/following-sibling::td/span/text()').get()
    gained_access = selector.xpath('//th[contains(text(), "Gained Access")]/following-sibling::td/span/text()').get()
    vulnerability_types = selector.xpath('//th[contains(text(), "Vulnerability Type(s)")]/following-sibling::td/span/text()').get()
    products = self.extract_vulnerable_products(selector)
    affected_versions = self.extract_affected_versions(selector)


    date_note = selector.xpath('//div[@class="cvedetailssummary"]/span[@class="datenote"]/text()').get()
    publish_date,last_update_date = self.parse_date(date_note)


    item = {
        'cvss_score': self.clean_string(cvss_score),
        'confidentiality_impact': self.clean_string(confidentiality_impact),
        'integrity_impact': self.clean_string(integrity_impact),
        'availability_impact': self.clean_string(availability_impact),
        'access_complexity': self.clean_string(access_complexity),
        'authentication': self.clean_string(authentication),
        'gained_access': self.clean_string(gained_access),
        'vulnerability_types': self.clean_string(vulnerability_types),
        'vulnerable_products': products,
        'affected_versions': affected_versions,
        'publish_date': publish_date,
        'last_update_date': last_update_date
    }
    yield item


  # Extract Number of Affected Versions by Product
  def extract_affected_versions(self, selector):
    affected_versions = []
    version_rows = selector.xpath('//table[@id="vulnversconuttable"]//tr[position() > 1]')
    for row in version_rows:
      vendor = self.clean_string(row.xpath('./td[1]/a/text()').get())
      product = self.clean_string(row.xpath('./td[2]/a/text()').get())
      num_versions = self.clean_string(row.xpath('./td[3]/text()').get().strip())
      if vendor!="" and product!="" and num_versions!="":
        affected_versions.append({
            'vendor': vendor,
            'product': product,
            'num_versions': num_versions
        })
    return affected_versions

  # Extract Vulnerable Products
  def extract_vulnerable_products(self, selector):
    products = []
    product_rows = selector.xpath('//table[@id="vulnprodstable"]//tr[position() > 1]')
    for row in product_rows:
      product_type = self.clean_string(row.xpath('./td[2]/text()').get())
      vendor = self.clean_string(row.xpath('./td[3]/a/text()').get())
      product = self.clean_string(row.xpath('./td[4]/a/text()').get())
      version = self.clean_string(row.xpath('./td[5]/text()').get())
      update = self.clean_string(row.xpath('./td[6]/text()').get())
      edition = self.clean_string(row.xpath('./td[7]/text()').get())
      language = self.clean_string(row.xpath('./td[8]/a/text()').get())
      if product!="" and vendor!="":
        products.append({
            'product_type': product_type,
            'vendor': vendor,
            'product': product,
            'version': version,
            'update': update,
            'edition': edition,
            'language': language
        })
    return products

  # Parse the date from the html element
  def parse_date(self, date_note):
    publish_date = None
    last_update_date = None
    if date_note:
      date_parts = date_note.split('Last Update Date :')
      if len(date_parts) == 2:
        publish_date_str = date_parts[0].strip().replace('Publish Date :', '')
        last_update_date_str = date_parts[1].strip()
        try:
          publish_date = datetime.strptime(publish_date_str.strip(), '%Y-%m-%d').date()
          last_update_date = datetime.strptime(last_update_date_str.strip(), '%Y-%m-%d').date()
        except ValueError as e:
          print("Error:", e)
    return publish_date, last_update_date

  #Clean the string to remove extra spaces and new lines
  #TODO: Add more cleaning
  def clean_string(self, string):
    if string==None: return ''
    return string.strip()

  #Write the output to the DB
  def write_db(self, item):
    pass
