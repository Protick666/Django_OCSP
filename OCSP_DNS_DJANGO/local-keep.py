DATABASES = {

    'default': {

        'ENGINE': 'django.db.backends.postgresql_psycopg2',

        'NAME': 'ocsp',

        'USER': 'postgres',

        'PASSWORD': 'postgres',

        'HOST': 'localhost',

        'PORT': '5432'

    }

}

INTERVAL_TYPE = 'hours'
INTERVAL_VAL = 1

LOCAL_REDIS_HOST = "pharah.cs.vt.edu"
REMOTE_REDIS_HOST = "pharah-db.cs.vt.edu"

LOCAL = True