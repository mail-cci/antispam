CREATE TABLE IF NOT EXISTS emails (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    correlation_id VARCHAR(36) NOT NULL,
    from_address VARCHAR(255),
    helo VARCHAR(255),
    host VARCHAR(255),
    port VARCHAR(10),
    addr VARCHAR(45),
    body TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_headers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email_id BIGINT,
    name VARCHAR(255),
    value TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email_id BIGINT,
    filename TEXT,
    content_type VARCHAR(255),
    data LONGBLOB,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS spam_scores (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email_id BIGINT,
    score FLOAT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS quarantine (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email_id BIGINT,
    reason TEXT,
    quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP NULL,
    FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
);

