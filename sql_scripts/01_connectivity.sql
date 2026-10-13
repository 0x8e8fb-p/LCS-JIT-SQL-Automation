-- Non-mutating sample: no schema or application data changes.
SELECT DB_NAME() AS database_name, SYSUTCDATETIME() AS server_utc;
GO
SELECT 1 AS connectivity_ok;
