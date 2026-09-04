-- Safe, additive migration. It never changes the existing database path.
-- mainbot.py also applies these defaults with INSERT OR IGNORE for idempotency.
INSERT OR IGNORE INTO settings(key,value) VALUES
('output_uri','1'),('output_json','1'),('output_original','1'),
('duplicate_filter','1'),('validation','1'),('logging_level','INFO'),
('max_configs','100'),('concurrency','4');
