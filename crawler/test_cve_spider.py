import unittest
from scrapy.http import HtmlResponse
from scrapy.utils.test import get_crawler
from scrapy import Selector
from cve_spider import Spider


class TestCVESpider(unittest.TestCase):
    def setUp(self):
        self.spider = Spider()
        self.crawler = get_crawler(self.spider.__class__)

    def test_parse_page(self):
        response = HtmlResponse(
            url='https://www.cvedetails.com/vulnerability-list/year-2022/vulnerabilities.html',
            body='''
        <html>
            <body>
                <div id="searchresults">
                    <table class="searchresults sortable">
                        <tr class="srrowns">
                            <td>...</td>
                            <td><a href="/vulnerability-details/cve-2022-1234/">CVE-2022-1234</a></td>
                        </tr>
                        <tr class="srrowns">
                            <td>...</td>
                            <td><a href="/vulnerability-details/cve-2022-5678/">CVE-2022-5678</a></td>
                        </tr>
                    </table>
                </div>
            </body>
        </html>
        ''',
            encoding='utf-8'
        )
        results = list(self.spider.parse_page(response))

        self.assertEqual(len(results), 2)
        self.assertEqual(
            results[0].url, 'https://www.cvedetails.com/vulnerability-details/cve-2022-1234/')
        self.assertEqual(
            results[1].url, 'https://www.cvedetails.com/vulnerability-details/cve-2022-5678/')

    def test_cve_parse(self):
        response = HtmlResponse(url='https://www.cvedetails.com/vulnerability-details/cve-2022-1234/',
                                body='''
        <table id="cvssscorestable" class="details">
            <tbody>
                <tr>
                    <th>CVSS Score</th>
                    <td><div class="cvssbox" style="background-color:#ff8000">8.5</div></td>
                </tr>
                <tr>
                    <th>Confidentiality Impact</th>
                    <td><span style="color:red">Complete</span>
                    <span class="cvssdesc">(There is total information disclosure, resulting in all system files being revealed.)</span></td>
                </tr>
                <tr>
                    <th>Integrity Impact</th>
                    <td><span style="color:red">Complete</span>
                    <span class="cvssdesc">(There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised.)</span></td>
                </tr>
                <tr>
                    <th>Availability Impact</th>
                    <td><span style="color:red">Complete</span>
                    <span class="cvssdesc">(There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.)</span></td>
                </tr>
                <tr>
                    <th>Access Complexity</th>
                    <td><span style="color:orange">Medium</span>
                    <span class="cvssdesc">(The access conditions are somewhat specialized. Some preconditions must be satisfied to exploit)</span></td>
                </tr>
                <tr>
                    <th>Authentication</th>
                    <td>???</td>
                </tr>
                <tr>
                    <th>Gained Access</th>
                    <td><span style="color:green;">None</span></td>
                </tr>
                <tr>
                    <th>Vulnerability Type(s)</th>
                    <td>
                    </td>
                </tr>
                <tr>
                    <th>CWE ID</th>
                    <td><a href="//www.cvedetails.com/cwe-details/59/cwe.html" title="CWE-59 - CWE definition">59</a></td>
                </tr>
            </tbody>
        </table>
        ''',
                                encoding='utf-8')
        results = list(self.spider.cve_parse(response))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['cvss_score'], '8.5')
        self.assertEqual(results[0]['confidentiality_impact'], 'Complete')
        self.assertEqual(results[0]['integrity_impact'], 'Complete')
        self.assertEqual(results[0]['availability_impact'], 'Complete')
        self.assertEqual(results[0]['access_complexity'], 'Medium')
        self.assertEqual(results[0]['authentication'], '')
        self.assertEqual(results[0]['gained_access'], 'None')
        self.assertEqual(results[0]['vulnerability_types'], '')

    def test_extract_affected_versions(self):
        selector = Selector(text='''
        <table class="listtable" id="vulnversconuttable">
					<tbody><tr>
						<th>
							Vendor
						</th>
						<th>
							Product
						</th>
						<th>
							Vulnerable Versions
						</th>
					</tr>
												<tr>
								<td>
									<a href="/vendor/28723/Drachtio.html" title="Details for Drachtio">Drachtio</a>								</td>
								<td><a href="/product/123777/Drachtio-Drachtio-server.html?vendor_id=28723" title="Product Details Drachtio Drachtio-server">Drachtio-server</a></td>
								<td class="num">
									 1								</td>
							</tr>
       <tr>
								<td>
									<a href="/vendor/28723/Drachtio.html" title="Details for Drachtio">Drachtio2</a>								</td>
								<td><a href="/product/123777/Drachtio-Drachtio-server.html?vendor_id=28723" title="Product Details Drachtio Drachtio-server">Drachtio-server</a></td>
								<td class="num">
									 1								</td>
							</tr>

										</tbody></table>
    ''')
        results = self.spider.extract_affected_versions(selector)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['vendor'], 'Drachtio')
        self.assertEqual(results[0]['product'], 'Drachtio-server')
        self.assertEqual(results[0]['num_versions'], '1')
        self.assertEqual(results[1]['vendor'], 'Drachtio2')
        self.assertEqual(results[1]['product'], 'Drachtio-server')
        self.assertEqual(results[1]['num_versions'], '1')

    def test_extract_vulnerable_products(self):
        selector = Selector(text='''
        <table class="listtable" id="vulnprodstable">
			<tbody><tr>
				<th class="num">#</th>
				<th>Product Type</th>
				<th>Vendor</th>
				<th>Product</th>
				<th>Version</th>
				<th>Update</th>
				<th>Edition</th>
				<th>Language</th>
								<th></th>
			</tr>
																																	<tr>
							<td class="num">
								1							</td>
							<td>
								Application							</td>
							<td>
								<a href="/vendor/9858/Vicidial.html" title="Details for Vicidial">Vicidial</a>							</td>
							<td>
								<a href="/product/27215/Vicidial-Vicidial.html?vendor_id=9858" title="Product Details Vicidial Vicidial">Vicidial</a>							</td>
							<td>
								2.14b0.5							</td>
							<td>
								3555							</td>
							<td>
								*							</td>
							<td>
								*							</td>
														<td>
								 <a href="/version/695043/Vicidial-Vicidial-2.14b0.5.html" title="Vicidial Vicidial 2.14b0.5">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-9858/product_id-27215/version_id-695043/Vicidial-Vicidial-2.14b0.5.html" title="Vulnerabilities of Vicidial Vicidial 2.14b0.5">Vulnerabilities</a>							</td>
						</tr>


									<script language="javascript" type="text/javascript">
												cvevalset('s_vprods',1);
					</script>
						</tbody></table>
    ''')
        results = self.spider.extract_vulnerable_products(selector)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['product_type'], 'Application')
        self.assertEqual(results[0]['vendor'], 'Vicidial')
        self.assertEqual(results[0]['product'], 'Vicidial')
        self.assertEqual(results[0]['version'], '2.14b0.5')
        self.assertEqual(results[0]['update'], '3555')
        self.assertEqual(results[0]['edition'], '*')
        self.assertEqual(results[0]['language'], '')

    def test_parse_date(self):
        publish_date, last_update_date = self.spider.parse_date(
            'Publish Date : 2022-01-01 Last Update Date : 2022-01-02')
        self.assertEqual(publish_date.strftime('%Y-%m-%d'), '2022-01-01')
        self.assertEqual(last_update_date.strftime('%Y-%m-%d'), '2022-01-02')

    def test_clean_string(self):
        cleaned_string = self.spider.clean_string('\n   Example String   \n')
        self.assertEqual(cleaned_string, 'Example String')

    def test_write_db(self):
        result = self.spider.write_db(None)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
