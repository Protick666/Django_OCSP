# Generated by Django 3.2.4 on 2021-06-08 16:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ocsp_url_db',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=300, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'ocsp_host',
            },
        ),
        migrations.CreateModel(
            name='ocsp_data',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('serial', models.CharField(max_length=1000)),
                ('akid', models.CharField(max_length=1000)),
                ('fingerprint', models.CharField(max_length=1000)),
                ('ocsp_response_status', models.CharField(max_length=1000)),
                ('delegated_response', models.BooleanField(default=False)),
                ('ocsp_response', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ocsp_url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='OCSP_DNS_DJANGO.ocsp_url_db')),
            ],
            options={
                'db_table': 'ocsp_data',
            },
        ),
        migrations.CreateModel(
            name='dns_record',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(max_length=100)),
                ('record', models.CharField(max_length=1000)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('ocsp_url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='OCSP_DNS_DJANGO.ocsp_url_db')),
            ],
            options={
                'db_table': 'ocsp_host_dns_record',
            },
        ),
    ]
