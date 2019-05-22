# Our new database conventions

The rules described in this document takes precedence, antyhing not specified here follow [sqlstyle.guide](https://www.sqlstyle.guide/). In case of any doubt use common sense.

# Naming conventions

 * Database name is singular
 * Table names is plural
 * Columns are singular
 * Snakecase is used
 * All datatimes have the prefix `_at`

If primary key is int auto increment use database name as singular `_id`.

## Linking tables

 * Describe `has` or `is` relationship

## Timestamps

Use:
 * created_at
 * updated_at

Note: Created at means this record is created at, updated at means this record is updated at.
