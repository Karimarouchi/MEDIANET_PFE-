ALTER TABLE IF EXISTS repositories
    ADD COLUMN IF NOT EXISTS git_provider VARCHAR(255);

UPDATE repositories
SET git_provider = CASE
    WHEN repo_url ILIKE '%gitlab.com%' THEN 'GITLAB'
    ELSE 'GITHUB'
END
WHERE git_provider IS NULL OR TRIM(git_provider) = '';

ALTER TABLE IF EXISTS repositories
    ALTER COLUMN git_provider SET DEFAULT 'GITHUB';

ALTER TABLE IF EXISTS repositories
    ALTER COLUMN git_provider SET NOT NULL;

ALTER TABLE IF EXISTS users
    ADD COLUMN IF NOT EXISTS suspended BOOLEAN;

UPDATE users
SET suspended = FALSE
WHERE suspended IS NULL;

ALTER TABLE IF EXISTS users
    ALTER COLUMN suspended SET DEFAULT FALSE;

ALTER TABLE IF EXISTS users
    ALTER COLUMN suspended SET NOT NULL;