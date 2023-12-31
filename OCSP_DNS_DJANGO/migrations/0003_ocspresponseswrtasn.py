# Generated by Django 3.2.4 on 2021-06-25 05:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('OCSP_DNS_DJANGO', '0002_ocsp_data_luminati'),
    ]

    operations = [
        migrations.CreateModel(
            name='OcspResponsesWrtAsn',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('serial', models.CharField(max_length=1000)),
                ('akid', models.CharField(max_length=1000)),
                ('fingerprint', models.CharField(max_length=1000)),
                ('ocsp_response_status', models.CharField(blank=True, max_length=1000, null=True)),
                ('ocsp_cert_status', models.CharField(blank=True, max_length=1000, null=True)),
                ('delegated_response', models.BooleanField(default=False)),
                ('ocsp_response', models.TextField(blank=True, null=True)),
                ('luminati_headers', models.TextField(blank=True, null=True)),
                ('country_code', models.CharField(max_length=1000)),
                ('asn', models.CharField(max_length=1000)),
                ('error', models.TextField(blank=True, null=True)),
                ('has_error', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('ocsp_url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='OCSP_DNS_DJANGO.ocsp_url_db')),
            ],
            options={
                'db_table': 'ocsp_response_wrt_asn',
                'unique_together': {('ocsp_url', 'serial', 'asn')},
            },
        ),
    ]
