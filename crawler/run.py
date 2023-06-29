from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings
from cve_spider import Spider


def run():
    settings = get_project_settings()
    settings.set('BOT_NAME', 'CVE_DATA')
    settings.set('DOWNLOAD_FAIL_ON_DATALOSS', False)
    settings.set('RETRY_ENABLED', True)
    settings.set('RETRY_TIMES', 5)
    settings.set('RETRY_HTTP_CODES', [500, 502, 503, 504, 522, 524, 408])
    settings.set('LOG_ENABLED', True)
    settings.set('LOG_LEVEL', 'INFO')
    settings.set('LOG_FORMAT', '%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    settings.set('LOG_DATEFORMAT', '%Y-%m-%d %H:%M:%S')
    settings.set('JOBDIR', 'crawls/cve_spider')
    settings.set('ITEM_PIPELINES', {
        'pipelines.SQLitePipeline': 300,
    })
    settings.set('SQLITEPIPELINE_CONNECTION_STRING', 'sqlite:///your_database_path')

    process = CrawlerProcess(settings=settings)
    process.crawl(Spider)
    process.start()

if __name__ == '__main__':
    run()
