from django.db import models

ASN, CN = 'ASN', 'CN'

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



class ocsp_data_luminati(models.Model):
    ocsp_url = models.ForeignKey(ocsp_url_db, on_delete=models.CASCADE)
    serial = models.CharField(max_length=1000)
    akid = models.CharField(max_length=1000)
    fingerprint = models.CharField(max_length=1000)
    ocsp_response_status = models.CharField(max_length=1000, null=True, blank=True)
    ocsp_cert_status = models.CharField(max_length=1000, null=True, blank=True)
    delegated_response = models.BooleanField(default=False)
    ocsp_response = models.TextField(null=True, blank=True)

    luminati_headers = models.TextField(null=True, blank=True)

    country_verbose_name = models.CharField(max_length=1000)
    country_code = models.CharField(max_length=1000)
    error = models.TextField(null=True, blank=True)
    has_error = models.BooleanField(default=False)


    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        db_table = 'ocsp_data_luminati'


class OcspResponsesWrtAsn(models.Model):
    ocsp_url = models.ForeignKey(ocsp_url_db, on_delete=models.CASCADE)

    serial = models.CharField(max_length=1000)
    akid = models.CharField(max_length=1000)
    fingerprint = models.CharField(max_length=1000)

    ocsp_response_status = models.CharField(max_length=1000, null=True, blank=True)
    ocsp_cert_status = models.CharField(max_length=1000, null=True, blank=True)
    delegated_response = models.BooleanField(default=False)
    # ocsp_response = models.TextField(null=True, blank=True)
    ocsp_response_as_bytes = models.BinaryField(null=True, blank=True)

    luminati_headers = models.TextField(null=True, blank=True)

    node_meta = models.TextField(null=True, blank=True)

    country_code = models.CharField(max_length=1000, null=True, blank=True)
    hop = models.CharField(max_length=1000)

    error = models.TextField(null=True, blank=True)
    has_error = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)
    updated_at = models.DateTimeField(auto_now_add=False, auto_now=True)

    # TODO check change
    mode = models.CharField(max_length=1000, default=ASN)

    class Meta:
        db_table = 'ocsp_response_wrt_asn'
        unique_together = ('ocsp_url', 'serial', 'hop', 'mode')


class dns_record(models.Model):
    ocsp_url = models.ForeignKey(ocsp_url_db, on_delete=models.CASCADE)
    type = models.CharField(max_length=100)
    record = models.CharField(max_length=1000)

    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        db_table = 'ocsp_host_dns_record'



