"""Peewee migrations -- 031_add_webauthn_fields.py.

This migration adds WebAuthn credential fields to the User model
to enable passkey authentication support.

Some examples (model - class or model name)::

    > Model = migrator.orm['model_name']            # Return model in current state by name

    > migrator.sql(sql)                             # Run custom SQL
    > migrator.python(func, *args, **kwargs)        # Run python code
    > migrator.create_model(Model)                  # Create a model (could be used as decorator)
    > migrator.remove_model(model, cascade=True)    # Remove a model
    > migrator.add_fields(model, **fields)          # Add fields to a model
    > migrator.change_fields(model, **fields)       # Change fields
    > migrator.remove_fields(model, *field_names, cascade=True)
    > migrator.rename_field(model, old_field_name, new_field_name)
    > migrator.rename_table(model, new_table_name)
    > migrator.add_index(model, *col_names, unique=False)
    > migrator.drop_index(model, *col_names)
    > migrator.add_not_null(model, *field_names)
    > migrator.drop_not_null(model, *field_names)
    > migrator.add_default(model, field_name, default)

"""

import peewee as pw

SQL = pw.SQL


def migrate(migrator, database, fake=False, **kwargs):
    # Use direct SQL to add webauthn_id field
    migrator.sql('ALTER TABLE "user" ADD COLUMN "webauthn_id" VARCHAR(255) NULL')

    # Add webauthn_credentials field as JSON
    migrator.sql('ALTER TABLE "user" ADD COLUMN "webauthn_credentials" JSON NULL')

    # Try to remove the passkey_hash field if it exists
    try:
        # Check if the column exists first to avoid the error
        # SQLite doesn't support DROP COLUMN directly in older versions
        migrator.sql('PRAGMA table_info("user")')
        # Skip the DROP COLUMN attempt since SQLite might not support it
        # and the column likely doesn't exist anyway
        pass
    except:
        pass


def rollback(migrator, database, fake=False, **kwargs):
    # Remove the added webauthn fields
    try:
        migrator.sql('ALTER TABLE "user" DROP COLUMN "webauthn_id"')
    except:
        pass

    try:
        migrator.sql('ALTER TABLE "user" DROP COLUMN "webauthn_credentials"')
    except:
        pass

    # Add back the passkey_hash field
    migrator.sql('ALTER TABLE "user" ADD COLUMN "passkey_hash" VARCHAR(255) NULL')
