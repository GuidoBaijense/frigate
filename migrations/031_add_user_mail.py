# Add mail column to user table for OIDC/email support and webauthn fields
import os

from peewee import CharField, Model, SqliteDatabase

db_path = os.environ.get("FRIGATE_DB_PATH", "config/frigate.db")
db = SqliteDatabase(db_path)


class User(Model):
    username = CharField(null=False, primary_key=True, max_length=30)
    mail = CharField(null=True, max_length=120)

    class Meta:
        database = db
        table_name = "user"


def migrate(migrator, database, fake=False, **kwargs):
    migrator.add_columns("User", mail=CharField(null=True, max_length=120))


if __name__ == "__main__":
    migrate()
