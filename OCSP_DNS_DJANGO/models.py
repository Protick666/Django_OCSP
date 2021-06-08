from django.db import models


class ocsp_url_db(models.Model):
    url = models.CharField(max_length=300, unique=True)

    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        db_table = 'ocsp_host'


class ocsp_data(models.Model):
    ocsp_url = models.ForeignKey(ocsp_url_db, on_delete=models.CASCADE)
    serial = models.CharField(max_length=1000)
    akid = models.CharField(max_length=1000)
    fingerprint = models.CharField(max_length=1000)
    ocsp_response_status = models.CharField(max_length=1000)
    delegated_response = models.BooleanField(default=False)
    ocsp_response = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        db_table = 'ocsp_data'


class dns_record(models.Model):
    ocsp_url = models.ForeignKey(ocsp_url_db, on_delete=models.CASCADE)
    type = models.CharField(max_length=100)
    record = models.CharField(max_length=1000)

    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        db_table = 'ocsp_host_dns_record'



