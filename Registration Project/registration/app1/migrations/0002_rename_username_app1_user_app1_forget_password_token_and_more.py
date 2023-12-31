# Generated by Django 4.2.2 on 2023-08-10 16:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='app1',
            old_name='username',
            new_name='user',
        ),
        migrations.AddField(
            model_name='app1',
            name='Forget_password_token',
            field=models.CharField(default='not_set', max_length=150),
        ),
        migrations.AlterField(
            model_name='app1',
            name='Email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
