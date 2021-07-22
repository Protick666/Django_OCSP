# runapscheduler.py
import logging

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from django.conf import settings
from django.core.management.base import BaseCommand
from django_apscheduler.jobstores import DjangoJobStore
from OCSP_DNS_DJANGO.luminati_async_asn_v2 import *

logger = logging.getLogger(__name__)


def my_job():
    luminati_master_crawler_async_v2()


class Command(BaseCommand):
    help = "Runs APScheduler."

    def handle(self, *args, **options):
        scheduler = BlockingScheduler(timezone=settings.TIME_ZONE)
        #scheduler.print_jobs()
        scheduler.remove_all_jobs()
        #scheduler.print_jobs()

        scheduler.add_jobstore(DjangoJobStore(), "default")

        scheduler.add_job(
            my_job,
            trigger=CronTrigger(hour=23, minute=0, second=0),  # Every 10 seconds
            id="luminati_ocsp_crawling",  # The `id` assigned to each job MUST be unique
            max_instances=1,
            replace_existing=True,
        )
        logger.info("Added job 'luminati_ocsp_crawling'.")

        try:
            logger.info("Starting scheduler...")
            scheduler.start()
        except KeyboardInterrupt:
            logger.info("Stopping scheduler...")
            scheduler.shutdown()
            logger.info("Scheduler shut down successfully!")